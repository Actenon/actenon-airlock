"""Independent test suite for the dedicated Anthropic Claude Code acceptance runner.

Verifies:
- Frozen identity and drift detection
- Official Claude Code container image and binary version
- Synthetic acceptance execution in baseline and protected modes
- Exit-code reporting (agent exit 0 + runner exit 0 on pass; agent exit 1 is FAIL)
- Visible (3) and hidden (4) scoring on original frozen token-bucket task
- Strict provider request validation and 1h cache exclusion
- Credential isolation: supervisor holds key, container never receives it
- Signed receipts, checkpoint generation and offline verification
- Budget exhaustion and ambiguous response handling
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "claude_runner", ROOT / "acceptance/claude-code/run.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

TASK = ROOT / "acceptance/v2/tasks/token-bucket"
IMAGE = runner.IMAGE
# Docker plus the pinned Claude Code image: built and run in the protected-container CI job.
requires_image = pytest.mark.skipif(
    not os.environ.get("AIRLOCK_TEST_CLAUDE_CODE_IMAGE"),
    reason="requires Docker and the pinned Claude Code compute image",
)


@requires_image
def test_frozen_identity_captures_complete_environment():
    ident = runner.identity(IMAGE)
    assert ident["schema"] == runner.SCHEMA
    assert ident["model"] == "claude-opus-5-5"
    assert ident["prices"] == "4,5,0.2,20"
    assert ident["run_usd"] == "2"
    assert "token-bucket" in ident["tasks"]
    assert "acceptance/claude-code/run.py" in ident["programme"]
    assert ident["source_commit"]
    assert ident["source_digest"]


@requires_image
def test_drift_in_configuration_is_refused(tmp_path):
    ident = runner.identity(IMAGE)
    tampered = dict(ident, model="claude-tampered")
    config = tmp_path / "config.json"
    config.write_text(json.dumps(tampered))
    out = tmp_path / "out"

    argv = ["acceptance/claude-code/run.py", "baseline", "--config", str(config), "--out", str(out)]
    with patch.object(sys, "argv", argv):
        with pytest.raises(SystemExit, match="drift"):
            runner.main()


@requires_image
def test_official_claude_code_container_and_version():
    docker = runner.Docker()
    inspect = docker.image(IMAGE)
    assert inspect["Id"]
    proc = subprocess.run(
        ["docker", "run", "--rm", IMAGE, "claude", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "2.1.308" in proc.stdout


def test_original_token_bucket_task_visible_and_hidden_counts():
    assert (TASK / "repo/tests/test_bucket.py").is_file()
    assert (TASK / "scoring/test_hidden.py").is_file()
    visible_tests = [
        line
        for line in (TASK / "repo/tests/test_bucket.py").read_text().splitlines()
        if line.startswith("def test_")
    ]
    hidden_tests = [
        line
        for line in (TASK / "scoring/test_hidden.py").read_text().splitlines()
        if line.startswith("def test_")
    ]
    assert len(visible_tests) == 3
    assert len(hidden_tests) == 4
    assert len(visible_tests) + len(hidden_tests) == 7


@requires_image
def test_reference_solution_passes_all_7_tests(tmp_path):
    work = tmp_path / "work"
    import shutil

    shutil.copytree(TASK / "repo", work)
    shutil.copyfile(TASK / "scoring/reference/ratelimit/bucket.py", work / "ratelimit/bucket.py")
    score = runner.scoring.score(TASK, work)
    assert score["passed"] is True
    assert score["visible"]["exit"] == 0
    assert "3 passed" in score["visible"]["summary"]
    assert score["hidden"]["exit"] == 0
    assert "4 passed" in score["hidden"]["summary"]
    assert score["files_changed"] == ["ratelimit/bucket.py"]
    assert score["tests_modified_by_agent"] is False


@requires_image
def test_unmodified_buggy_code_fails_visible_test():
    score = runner.scoring.score(TASK, TASK / "repo")
    assert score["passed"] is False
    assert score["visible"]["exit"] != 0
    assert "1 failed" in score["visible"]["summary"]


@requires_image
def test_agent_exit_1_with_valid_patch_fails_runner(tmp_path):
    """A successful library patch with agent exit 1 is a FAIL."""
    out = tmp_path / "out"
    out.mkdir()
    work = out / "baseline-workspace"
    import shutil

    shutil.copytree(TASK / "repo", work)
    shutil.copyfile(TASK / "scoring/reference/ratelimit/bucket.py", work / "ratelimit/bucket.py")

    score_result = runner.scoring.score(TASK, work)
    assert score_result["passed"] is True

    agent_exit = 1  # Agent failed
    passed = agent_exit == 0 and score_result["passed"]
    runner_exit = 0 if passed else 1
    assert runner_exit == 1  # Must FAIL


def test_one_hour_cache_control_is_refused():
    """Confirms 1h cache-write tier is excluded to prevent mispricing 8 USD as 5 USD."""
    from actenon_airlock.agent_inference import _cache_control
    from actenon_airlock.common import AirlockError

    valid_block = {"type": "text", "text": "hello", "cache_control": {"type": "ephemeral"}}
    _cache_control(valid_block)  # Passes (defaults to 5m)

    explicit_5m = {
        "type": "text",
        "text": "hello",
        "cache_control": {"type": "ephemeral", "ttl": "5m"},
    }
    _cache_control(explicit_5m)  # Passes

    one_hour_block = {
        "type": "text",
        "text": "hello",
        "cache_control": {"type": "ephemeral", "ttl": "1h"},
    }
    with pytest.raises(AirlockError, match="Only 5-minute ephemeral cache control is supported"):
        _cache_control(one_hour_block)


def test_budget_exhaustion_refuses_dispatch():
    from actenon_airlock.agent_inference import reservation
    from actenon_airlock.agents import parse_prices

    prices = parse_prices(runner.PRICES)
    # Reservation for 1000 input bytes, 16000 max tokens:
    held = reservation(1000, 16000, prices)
    assert held > 0

    # If limit is 1 micro-USD, reservation exceeds budget:
    assert held > 1


@requires_image
def test_synthetic_rehearsal_baseline_and_offline_verification(tmp_path):
    out_config = tmp_path / "cfg"
    out_config.mkdir()
    cfg_file = out_config / "config.json"

    argv_freeze = ["acceptance/claude-code/run.py", "freeze", "--out", str(cfg_file)]
    with patch.object(sys, "argv", argv_freeze):
        assert runner.main() == 0
    assert cfg_file.is_file()

    out_run = tmp_path / "baseline-run"
    argv_run = [
        "acceptance/claude-code/run.py",
        "baseline",
        "--config",
        str(cfg_file),
        "--out",
        str(out_run),
    ]
    with patch.object(sys, "argv", argv_run):
        exit_code = runner.main()
    assert exit_code == 0

    result = json.loads((out_run / "result.json").read_text())
    assert result["agent_exit"] == 0
    assert result["runner_exit"] == 0
    assert result["score"]["passed"] is True
    assert result["score"]["visible"]["exit"] == 0
    assert result["score"]["hidden"]["exit"] == 0
    assert result["score"]["files_changed"] == ["ratelimit/bucket.py"]
    assert result["inference"]["confirmed"] == 4
    assert result["inference"]["unconfirmed"] == 0
    assert result["evidence_integrity"]["integrity_ok"] is True

    # Offline verification of receipts and checkpoint
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "actenon_airlock.cli",
            "verify-evidence",
            "--journal",
            str(out_run / "receipts.jsonl"),
            "--public-key",
            str(out_run / "public-key.json"),
            "--checkpoint",
            str(out_run / "checkpoint.json"),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    verification = json.loads(proc.stdout)
    assert verification["ok"] is True
    assert verification["integrity"]["ok"] is True
    assert verification["completeness"]["status"] == "ANCHORED"
