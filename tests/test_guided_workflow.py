"""The guided path: capture, verify, approve exact bytes, publish, independently settle.

Only the HTTP transport is synthetic. Grants, signatures, durable claims, receipts
and the broker are the real integrated components.
"""

import hashlib
import json
import os
import shutil
import threading
import time
from pathlib import Path

import pytest

from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.github_consequence import MAX_CONTENT_BYTES
from actenon_airlock.protected import launch_protected
from actenon_airlock.state import State
from actenon_airlock.synthetic_github import synthetic_client
from actenon_airlock.workflow import (
    TESTS_FAILED,
    TESTS_PASSED,
    _observed,
    capture_candidate,
    publish_candidate,
    status,
    verify_candidate,
)

ENDPOINT = "http://127.0.0.1:11435/v1/chat/completions"


class Project:
    def __init__(self, base: Path):
        self.root = base / "project"
        self.root.mkdir()
        (self.root / "app.py").write_text("def add(a, b):\n    return a - b\n")
        self.key = base / "observer.key"
        self.provider = base / "provider.json"
        assert (
            main(
                [
                    "setup", "--path", str(self.root), "--agent", "aider", "--model", "test-model",
                    "--model-endpoint", ENDPOINT, "--reconciler-key", str(self.key), "--approve",
                ]
            )
            == 0
        )  # fmt: skip
        assert main(["synthetic-provider", "--file", str(self.provider), "--create"]) == 0
        self.state = State(self.root)
        self.runs = 0

    def agent_writes(self, files: dict[str, str], *, links=()) -> Path:
        self.runs += 1
        run = self.state.local / "runs" / f"run{self.runs}"
        workspace = run / "workspace"
        shutil.copytree(self.root, workspace, ignore=shutil.ignore_patterns(".airlock"))
        for name, text in files.items():
            (workspace / name).write_text(text)
        for name, target in links:
            (workspace / name).symlink_to(target)
        (run / "result.json").write_text("{}")
        return run

    def candidate(self, text="def add(a, b):\n    return a + b\n") -> str:
        self.agent_writes({"app.py": text})
        return capture_candidate(self.state)["candidate_sha256"]

    def verified(self, sha256: str, verdict=TESTS_PASSED) -> None:
        _observed(
            self.state,
            "candidate.verify",
            "candidate:" + sha256,
            "fixture verification",
            stage="candidate-tests",
            candidate_sha256=sha256,
            verdict=verdict,
        )

    def approve(self, sha256: str, path="patches/fix.patch") -> None:
        profile = self.root.parent / "profile.json"
        common = ["--path", str(self.root)]
        assert (
            main(
                [
                    "review-candidate", *common, "--candidate", sha256, "--output", str(profile),
                    "--path-in-repo", path, "--message", "publish reviewed patch",
                    "--synthetic-provider", str(self.provider),
                ]
            )
            == 0
        )  # fmt: skip
        assert (
            main(
                [
                    "init", *common, "--approve", "--github-create", str(profile),
                    "--reconciler-key", str(self.key),
                    "--credential", "GITHUB_TOKEN=https://api.github.com",
                ]
            )
            == 0
        )  # fmt: skip

    def publish(self, sha256: str) -> dict:
        os.environ["GITHUB_TOKEN"] = "synthetic-github-token-not-a-real-credential"
        return publish_candidate(self.state, sha256, client=synthetic_client(self.provider))

    def reconcile(self, effect_id: str) -> int:
        return main(
            [
                "reconcile", "--path", str(self.root), effect_id, "--github-readback",
                "--operator-key", str(self.key), "--synthetic-provider", str(self.provider),
            ]
        )  # fmt: skip

    def world(self) -> dict:
        return json.loads(self.provider.read_text())

    def mutations(self) -> list[dict]:
        return [r for r in self.world()["requests"] if r["method"] == "PUT"]


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield Project(tmp_path)
    os.environ.pop("GITHUB_TOKEN", None)


def test_capture_records_exact_change_without_executing_it(project, tmp_path):
    marker = tmp_path / "executed"
    planted = f"open({str(marker)!r}, 'w').write('ran')\n"
    project.agent_writes({"app.py": "x = 1\n", "conftest.py": planted, "setup.py": planted})
    manifest = capture_candidate(project.state)
    assert {c["path"]: c["status"] for c in manifest["changes"]} == {
        "app.py": "modified",
        "conftest.py": "added",
        "setup.py": "added",
    }
    patch = project.state.local / "candidates" / manifest["candidate_sha256"] / "candidate.patch"
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == manifest["candidate_sha256"]
    assert manifest["trust"] == "untrusted agent output"
    assert not marker.exists()


def test_symlink_in_agent_output_refuses_the_whole_capture(project, tmp_path):
    secret = tmp_path / "host-secret"
    secret.write_text("host only")
    project.agent_writes({}, links=[("stolen.txt", secret)])
    with pytest.raises(AirlockError, match="link or special file"):
        capture_candidate(project.state)
    assert not (project.state.local / "candidates").exists()


def test_a_file_name_cannot_forge_lines_of_the_reviewed_diff(project):
    project.agent_writes({"x\n+forged line": "harmless\n"})
    with pytest.raises(AirlockError, match="unprintable"):
        capture_candidate(project.state)


def test_tested_tree_must_match_the_captured_change(project):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    tree = project.state.local / "candidates" / sha256 / "tree" / "app.py"
    tree.write_text("different bytes\n")
    with pytest.raises(AirlockError, match="changed since capture"):
        project.publish(sha256)
    with pytest.raises(AirlockError, match="changed since capture"):
        verify_candidate(project.state, sha256, project.root.parent)
    assert project.world()["requests"] == []


def test_setup_will_not_replace_a_projects_own_file(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    (root / "airlock_agent.py").write_text("print('mine')\n")
    code = main(
        [
            "setup", "--path", str(root), "--agent", "aider", "--model", "m",
            "--model-endpoint", ENDPOINT,
        ]
    )  # fmt: skip
    assert code != 0
    assert "already exists" in capsys.readouterr().err
    assert (root / "airlock_agent.py").read_text() == "print('mine')\n"


def test_message_file_must_reach_the_agent(project, tmp_path, capsys):
    outside = tmp_path / "issue.md"
    outside.write_text("do it")
    code = main(["work", "--path", str(project.root), "--message-file", str(outside)])
    assert code != 0
    assert "inside the project" in capsys.readouterr().err


def test_capture_refuses_oversized_binary_and_empty_output(project):
    project.agent_writes({})
    with pytest.raises(AirlockError, match="changed nothing"):
        capture_candidate(project.state)
    project.agent_writes({"big.txt": "x\n" * MAX_CONTENT_BYTES})
    with pytest.raises(AirlockError, match="64 KiB"):
        capture_candidate(project.state)
    run = project.agent_writes({})
    (run / "workspace" / "blob.bin").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(AirlockError, match="Binary change"):
        capture_candidate(project.state)


def test_an_unverified_or_failing_candidate_cannot_be_published(project):
    sha256 = project.candidate()
    project.approve(sha256)
    with pytest.raises(AirlockError, match="passing verification"):
        project.publish(sha256)
    project.verified(sha256, TESTS_FAILED)
    with pytest.raises(AirlockError, match="passing verification"):
        project.publish(sha256)
    project.verified(sha256)
    project.verified(sha256, TESTS_FAILED)  # the latest result governs
    with pytest.raises(AirlockError, match="passing verification"):
        project.publish(sha256)
    assert project.mutations() == []


def test_passing_tests_do_not_authorize_publication(project):
    sha256 = project.candidate()
    project.verified(sha256)
    with pytest.raises(AirlockError, match="do not authorize"):
        project.publish(sha256)
    assert project.world()["requests"] == []


def test_a_passing_variant_of_approved_bytes_is_refused(project):
    approved = project.candidate()
    project.approve(approved)
    variant = project.candidate("def add(a, b):\n    return a + b  # variant\n")
    assert variant != approved
    project.verified(variant)
    with pytest.raises(AirlockError, match="do not authorize"):
        project.publish(variant)
    assert project.world()["requests"] == []


def test_changed_candidate_bytes_are_refused_before_any_dispatch(project):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    patch = project.state.local / "candidates" / sha256 / "candidate.patch"
    patch.write_bytes(patch.read_bytes() + b"+extra\n")
    with pytest.raises(AirlockError, match="changed since capture"):
        project.publish(sha256)
    assert project.world()["requests"] == []


def test_exact_creation_stays_unconfirmed_until_readback_settles_it(project):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    result = project.publish(sha256)
    # Even a provider 201 is a claim; only an independent readback settles it.
    assert (result["status"], result["outcome"]) == ("DISPATCHED_UNCONFIRMED", "AMBIGUOUS")
    assert len(project.mutations()) == 1
    assert status(project.state)["independently_observed"] == {}
    assert status(project.state)["unresolved_effects"] == [result["effect_id"]]
    assert project.reconcile(result["effect_id"]) == 0
    world = project.world()
    assert list(world["files"]) == ["patches/fix.patch"]
    assert status(project.state)["independently_observed"] == {"COMMITTED": 1}
    assert status(project.state)["unresolved_effects"] == []
    assert len(project.mutations()) == 1


def test_lost_acknowledgement_never_redispatches_and_stays_ambiguous(project, capsys):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    assert main(["synthetic-provider", "--file", str(project.provider), "--lose-next-ack"]) == 0
    first = project.publish(sha256)
    assert (first["status"], first["outcome"]) == ("AMBIGUOUS", "AMBIGUOUS")
    assert first["effect_id"]
    assert status(project.state)["unresolved_effects"] == [first["effect_id"]]
    # A new process, a new grant, a new request: the provider must see no second write.
    for _ in range(3):
        assert project.publish(sha256)["status"] == "REFUSED"
    assert len(project.mutations()) == 1
    assert status(project.state)["unresolved_effects"] == [first["effect_id"]]
    assert project.reconcile(first["effect_id"]) == 0
    assert status(project.state)["independently_observed"] == {"COMMITTED": 1}
    assert project.publish(sha256)["status"] == "REFUSED"
    assert len(project.mutations()) == 1


def test_readback_of_altered_provider_content_does_not_confirm(project):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    result = project.publish(sha256)
    world = project.world()
    world["files"]["patches/fix.patch"]["content"] = "dGFtcGVyZWQ="
    project.provider.write_text(json.dumps(world))
    project.reconcile(result["effect_id"])
    assert status(project.state)["independently_observed"].get("COMMITTED") is None


def test_emergency_stop_blocks_dispatch_but_not_settlement(project):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    first = project.publish(sha256)
    assert main(["stop", "--path", str(project.root), "--reason", "incident 42"]) == 0
    assert status(project.state)["emergency_stop"]["reason"] == "incident 42"
    assert project.publish(sha256)["reason"] == "Emergency stop is active"
    assert len(project.mutations()) == 1
    with pytest.raises(AirlockError, match="Emergency stop"):
        launch_protected(project.root, ["true"], image="no-such-image:never-built")
    # Read-only settlement is what an operator needs most during an incident.
    assert project.reconcile(first["effect_id"]) == 0
    assert status(project.state)["independently_observed"] == {"COMMITTED": 1}
    assert main(["resume", "--path", str(project.root), "--reason", "contained"]) == 0
    assert status(project.state)["emergency_stop"] is None
    # Resuming clears the stop, never a settled or held effect.
    assert project.publish(sha256)["status"] == "REFUSED"
    assert len(project.mutations()) == 1


def test_unreadable_stop_marker_still_stops(project):
    (project.state.local / "emergency-stop.json").write_text("{not json")
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    assert project.publish(sha256)["reason"] == "Emergency stop is active"
    assert project.mutations() == []


def test_rotating_the_credential_keeps_a_held_effect_held(project):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    assert main(["synthetic-provider", "--file", str(project.provider), "--lose-next-ack"]) == 0
    assert project.publish(sha256)["status"] == "AMBIGUOUS"
    os.environ["GITHUB_TOKEN"] = "rotated-synthetic-credential"
    retried = publish_candidate(project.state, sha256, client=synthetic_client(project.provider))
    assert retried["status"] == "REFUSED"
    assert len(project.mutations()) == 1
    assert b"rotated-synthetic-credential" not in project.state.receipts_path.read_bytes()


def test_revoking_approval_stops_publication_and_keeps_the_hold(project):
    sha256 = project.candidate()
    project.verified(sha256)
    project.approve(sha256)
    first = project.publish(sha256)
    assert main(["init", "--path", str(project.root), "--approve", "--clear-github"]) == 0
    with pytest.raises(AirlockError, match="do not authorize"):
        project.publish(sha256)
    assert status(project.state)["unresolved_effects"] == [first["effect_id"]]
    assert len(project.mutations()) == 1


def test_status_reports_an_edited_journal(project):
    project.candidate()
    assert status(project.state)["integrity_ok"]
    journal = project.state.receipts_path
    journal.write_bytes(journal.read_bytes().replace(b"candidate", b"Candidate", 1))
    assert not status(project.state)["integrity_ok"]


def test_setup_refuses_an_unsupported_agent(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    code = main(
        [
            "setup", "--path", str(root), "--agent", "other", "--model", "m",
            "--model-endpoint", ENDPOINT,
        ]
    )  # fmt: skip
    assert code != 0
    assert "Unsupported agent" in capsys.readouterr().err


def test_work_requires_setup_and_never_falls_back_to_local_mode(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    message = tmp_path / "issue.md"
    message.write_text("do it")
    code = main(["work", "--path", str(root), "--message-file", str(message)])
    assert code != 0
    assert "airlock setup" in capsys.readouterr().err


@pytest.mark.skipif(
    not os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE"),
    reason="requires a local protected image",
)
def test_verification_runs_trusted_tests_in_a_contained_container(project, tmp_path):
    image = os.environ["AIRLOCK_TEST_PROTECTED_IMAGE"]
    tests = tmp_path / "trusted"
    tests.mkdir()
    (tests / "test_add.py").write_text(
        "from app import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    )
    good = project.candidate()
    assert verify_candidate(project.state, good, tests, image=image)["verdict"] == TESTS_PASSED
    project.approve(good)
    bad = project.candidate("def add(a, b):\n    return 0\n")
    assert verify_candidate(project.state, bad, tests, image=image)["verdict"] == TESTS_FAILED
    with pytest.raises(AirlockError, match="outside the project"):
        verify_candidate(project.state, bad, project.root, image=image)


@pytest.mark.skipif(
    not os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE"),
    reason="requires a local protected image",
)
def test_emergency_stop_kills_a_running_protected_agent(project):
    image = os.environ["AIRLOCK_TEST_PROTECTED_IMAGE"]
    (project.root / "agent_sleep.py").write_text("import time\ntime.sleep(120)\n")
    assert (
        main(["init", "--path", str(project.root), "--approve", "--command", "agent_sleep.py"]) == 0
    )
    timer = threading.Timer(5, project.state.set_emergency_stop, args=("incident",))
    timer.start()
    began = time.monotonic()
    code = launch_protected(project.root, ["python3", "agent_sleep.py"], image=image)
    timer.join()
    assert time.monotonic() - began < 60
    assert code == 137
