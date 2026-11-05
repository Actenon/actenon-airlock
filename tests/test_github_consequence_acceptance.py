"""Gate 6 acceptance programme: offline refusals, referee verdicts and a full rehearsal."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "acceptance/github-consequence/run.py"
IMAGE = os.environ.get("AIRLOCK_TEST_CLAUDE_CODE_IMAGE")
ANTHROPIC = "sk-ant-api03-" + "Gate6SyntheticKey0123456789" * 3 + "-AA"
FACTS = {
    "repo_id": 1,
    "repo_node_id": "R_x",
    "owner": "owner",
    "repo": "disposable",
    "branch": "main",
    "expected_parent_sha": "a" * 40,
}

spec = importlib.util.spec_from_file_location("gate6_runner", RUNNER)
gate6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate6)


def secret(path: Path, value: str) -> Path:
    path.write_text(value + "\n")
    path.chmod(0o600)
    return path


def live(tmp_path, *, readback="ghp_readback_synthetic", facts=FACTS, authorize=None, **drop):
    (tmp_path / "facts.json").write_text(json.dumps(facts))
    authorize = authorize or f"owner/disposable@main:{gate6.PATH_IN_REPO}"
    args = {
        "--config": str(tmp_path / "freeze.json"),
        "--authorized-usd": "2",
        "--anthropic-credential-file": str(secret(tmp_path / "anthropic", ANTHROPIC)),
        "--github-credential-file": str(secret(tmp_path / "write", "ghp_write_synthetic")),
        "--readback-credential-file": str(secret(tmp_path / "read", readback)),
        "--repo-facts": str(tmp_path / "facts.json"),
        "--authorize-github-write": authorize,
    }
    for name in drop:
        args.pop("--" + name.replace("_", "-"))
    command = [sys.executable, str(RUNNER), "live", "--out", str(tmp_path / "out"),
               "--image", "not-a-real-image"]  # fmt: skip
    for name, value in args.items():
        command += [name, value]
    env = {k: v for k, v in os.environ.items() if k not in {"ANTHROPIC_API_KEY", "GITHUB_TOKEN"}}
    return subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"config": True}, "needs every credential file"),
        ({"readback": "ghp_write_synthetic"}, "must differ from the write credential"),
        ({"facts": {**FACTS, "extra": 1}}, "must name exactly"),
        ({"authorize": "owner/disposable@main:some/other/path"}, "must be exactly"),
    ],
)
def test_live_mode_refuses_locally_before_any_docker_or_network(tmp_path, changes, message):
    if changes.pop("config", False):
        result = live(tmp_path, config=True)
    else:
        result = live(tmp_path, **changes)
    assert result.returncode != 0 and message in result.stderr
    assert not (tmp_path / "out").exists()
    for value in (ANTHROPIC, "ghp_write_synthetic", "ghp_readback_synthetic"):
        assert value not in result.stdout + result.stderr


def verdict(**changes):
    values = {
        "content": b"patch",
        "content_sha256": gate6._sha(b"patch"),
        "parents": [FACTS["expected_parent_sha"]],
        "files": [gate6.PATH_IN_REPO],
        **changes,
    }
    return gate6.Referee._verdict(source="test", commit_sha="c" * 40, facts=FACTS, **values)


@pytest.mark.parametrize(
    "changes",
    [
        {"content": b"altered"},
        {"parents": ["b" * 40]},
        {"files": [gate6.PATH_IN_REPO, "other.txt"]},
        {"content": b""},
    ],
)
def test_referee_does_not_confirm_anything_but_the_reviewed_commit(changes):
    assert verdict()["confirmed"] is True
    assert verdict(**changes)["confirmed"] is False


@pytest.mark.skipif(not IMAGE, reason="requires Docker and the pinned Claude Code compute image")
def test_full_rehearsal_with_controls(tmp_path):
    env = {k: v for k, v in os.environ.items() if k not in {"ANTHROPIC_API_KEY", "GITHUB_TOKEN"}}
    out = tmp_path / "gate6"
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "rehearsal", "--out", str(out), "--image", IMAGE],
        env=env, capture_output=True, text=True, timeout=900,
    )  # fmt: skip
    assert completed.returncode == 0, completed.stderr[-3000:]
    result = json.loads((out / "result.json").read_text())
    controls = {c["control"]: c for c in result["controls"]}
    for name in ("publish-before-approval", "publish-altered-candidate", "unauthorised-path-write"):
        assert controls[name]["status"] == "REFUSED" and controls[name]["provider_puts_after"] == 0
    assert controls["unauthorised-path-write"]["credential_released"] is False
    assert controls["approved-publish"]["status"] == "AMBIGUOUS"  # acknowledgement lost
    assert result["effect_id"] in result["unresolved_before_readback"]
    assert controls["identical-replay"]["status"] == "REFUSED"
    assert result["independent_readback"]["provider_put_requests"] == 1
    assert result["independent_readback"]["confirmed"] is True
    assert result["airlock"]["independently_observed"] == {"COMMITTED": 1}
    assert result["airlock"]["unresolved_effects"] == []
    assert result["airlock"]["inference"]["unconfirmed"] == 0
    report = (out / "CONSEQUENCE.md").read_text()
    assert report.startswith("# Consequence report: CONFIRMED\n")
    assert "acknowledgement of the write never arrived" in report
