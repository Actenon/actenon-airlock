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
    for name in gate6.PRE_APPROVAL_CONTROLS:
        assert controls[name]["status"] == "REFUSED" and controls[name]["provider_puts_after"] == 0
    for name in ("unauthorised-path-write", "altered-repository-write",
                 "modified-payload-write", "update-exceeds-create"):  # fmt: skip
        assert controls[name]["credential_released"] is False, controls[name]
        assert controls[name]["decision"] == "DENY", controls[name]
    assert result["credentials_absent_from_agent_surfaces"] == {
        "github_write": True,
        "anthropic": True,
    }
    assert controls["approved-publish"]["status"] == "AMBIGUOUS"  # acknowledgement lost
    assert result["effect_id"] in result["unresolved_before_readback"]
    assert controls["identical-replay"]["status"] == "REFUSED"
    assert result["independent_readback"]["provider_put_requests"] == 1
    assert result["independent_readback"]["confirmed"] is True
    assert result["airlock"]["independently_observed"] == {"COMMITTED": 1}
    assert result["airlock"]["unresolved_effects"] == []
    assert result["airlock"]["inference"]["unconfirmed"] == 0
    report = (out / "CONSEQUENCE.md").read_text()
    assert report.startswith("# Consequence report: CONFIRMED\n\n" + gate6.REHEARSAL_NOTICE)
    assert "acknowledgement of the write never arrived" in report


def test_broker_controls_never_include_the_reviewed_write():
    patch = b"+fix\n"
    controls = gate6.broker_write_controls(FACTS, patch)
    assert [c[0] for c in controls] == list(gate6.PRE_APPROVAL_CONTROLS[2:])
    reviewed_url = f"{gate6.API}/repos/owner/disposable/contents/{gate6.PATH_IN_REPO}"
    reviewed_body = {"branch": "main", "message": gate6.MESSAGE, "content": "K2ZpeAo="}
    for _, url, fields in controls:
        assert (url, fields) != (reviewed_url, reviewed_body)


def test_credential_isolation_reports_names_never_values(tmp_path):
    (tmp_path / "run/workspace").mkdir(parents=True)
    (tmp_path / "run/workspace/notes.txt").write_text("leaked ghp_write_synthetic here")
    (tmp_path / "agent.log").write_text("clean")
    result = gate6.credentials_absent(
        [tmp_path / "run", tmp_path / "agent.log"],
        {
            "github_write": "ghp_write_synthetic",
            "github_readback": "ghp_read_synthetic",
            "none": "",
        },
    )
    assert result == {"github_write": False, "github_readback": True}


def proposed(tmp_path):
    profile = tmp_path / "reviewed-create.json"
    review = {"owner": "owner", "repo": "disposable", "branch": "main",
              "expected_parent_sha": "a" * 40, "path": gate6.PATH_IN_REPO,
              "message": gate6.MESSAGE, "content_sha256": "0123456789ab" + "c" * 52}  # fmt: skip
    profile.write_text(json.dumps({"review": review}))
    return profile


@pytest.mark.parametrize(
    "answer,approved",
    [
        ("0123456789ab", True),
        ("  0123456789AB  ", True),
        ("", False),
        ("y", False),
        ("0123456789a", False),
        (".venv/bin/python acceptance/github-consequence/run.py live --out x", False),
    ],
)
def test_owner_must_type_the_content_hash_prefix(tmp_path, answer, approved):
    shown = []
    result = gate6.owner_review(proposed(tmp_path), b"+patched line\n", ask=lambda _: answer,
                                show=shown.append)  # fmt: skip
    assert result["approved"] is approved
    text = "\n".join(shown)
    assert "+patched line" in text and gate6.PATH_IN_REPO in text and "a" * 40 in text


@pytest.mark.skipif(not IMAGE, reason="requires Docker and the pinned Claude Code compute image")
@pytest.mark.parametrize("answer", ["\n", "yes\n"])
def test_refused_owner_review_approves_and_writes_nothing(tmp_path, answer):
    env = {k: v for k, v in os.environ.items() if k not in {"ANTHROPIC_API_KEY", "GITHUB_TOKEN"}}
    out = tmp_path / "gate6"
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "rehearsal", "--out", str(out), "--image", IMAGE,
         "--interactive-approval"],
        input=answer, env=env, capture_output=True, text=True, timeout=900,
    )  # fmt: skip
    assert completed.returncode == 2, completed.stderr[-2000:]
    assert "nothing was written" in completed.stdout
    result = json.loads((out / "result.json").read_text())
    assert result["status"] == "STOPPED_BY_OWNER" and result["approval"]["approved"] is False
    world = json.loads((out / "provider.json").read_text())
    assert not [r for r in world["requests"] if r["method"] == "PUT"]
    approved = json.loads((out / "project/.airlock/approved.json").read_text())["payload"]
    assert not approved.get("protected_github")
