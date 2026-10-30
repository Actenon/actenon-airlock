"""The release workflow must make publication depend on admission, not report it afterwards."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _workflow(name: str) -> dict:
    data = yaml.safe_load((WORKFLOWS / name).read_text())
    data["on"] = data.pop(True, data.get("on"))  # YAML 1.1 reads `on:` as True
    return data


def _load_request_check():
    path = ROOT / "scripts" / "check_release_request.py"
    spec = importlib.util.spec_from_file_location("check_release_request", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _needs(job: dict) -> set[str]:
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


def test_every_release_side_effect_needs_admission() -> None:
    jobs = _workflow("release.yml")["jobs"]
    assert set(jobs) == {"admission", "build", "publish", "tag"}
    assert _needs(jobs["build"]) == {"admission"}
    assert _needs(jobs["publish"]) >= {"admission", "build"}
    assert _needs(jobs["tag"]) >= {"admission", "build", "publish"}
    for name, job in jobs.items():
        assert "if" not in job, f"{name} must not bypass its needs with a job-level condition"
        assert "continue-on-error" not in json.dumps(job)


def test_admission_runs_the_gate_at_release_ready_from_the_default_branch() -> None:
    admission = _workflow("release.yml")["jobs"]["admission"]
    steps = admission["steps"]
    assert "default_branch" in steps[0]["if"] and "exit 1" in steps[0]["run"]
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    commands = " ".join(s.get("run", "") for s in steps)
    assert "check_release_request.py" in commands
    assert "check_candidate_admission.py" in commands and '--require "RELEASE READY"' in commands


def test_release_is_manual_and_never_triggered_by_a_tag() -> None:
    for name in ("release.yml", "release-admission.yml"):
        triggers = _workflow(name)["on"]
        assert set(triggers) == {"workflow_dispatch"}, name


def test_permissions_are_least_privilege_per_job() -> None:
    workflow = _workflow("release.yml")
    assert workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert jobs["admission"]["permissions"].get("contents") == "read"
    assert "id-token" not in jobs["admission"]["permissions"]
    assert jobs["publish"]["permissions"] == {"id-token": "write"}
    assert jobs["publish"]["environment"] == "pypi-release"
    assert jobs["tag"]["permissions"] == {"contents": "write"}
    writers = [n for n, j in jobs.items() if j["permissions"].get("contents") == "write"]
    assert writers == ["tag"]


def test_actions_are_pinned_by_commit() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        for line in path.read_text().splitlines():
            if "uses:" in line:
                ref = line.split("uses:", 1)[1].strip().split("#")[0].strip()
                assert "@" in ref and len(ref.split("@", 1)[1]) == 40, f"{path.name}: {ref}"


@pytest.mark.parametrize(
    ("pyproject", "requested", "expected"),
    [
        (b'[project]\nversion = "1.0.0"\ndependencies = []\n', "1.0.0", []),
        (b'[project]\nversion = "1.0.0"\ndependencies = []\n', "1.0.1", ["declares"]),
        (b'[project]\nversion = "1.0.0rc1"\ndependencies = []\n', "1.0.0rc1", ["final"]),
        (b'[project]\nversion = "0.1.0.dev0"\n', "0.1.0.dev0", ["final"]),
        (
            b'[project]\nversion = "1.0.0"\ndependencies = ["x @ git+https://e/x@abc"]\n',
            "1.0.0",
            ["direct URL"],
        ),
        (None, "1.0.0", ["absent"]),
        (b"not toml [", "1.0.0", ["unreadable"]),
    ],
)
def test_release_request_refuses_mismatched_or_unreleasable_versions(
    pyproject, requested, expected
) -> None:
    found = _load_request_check().problems(pyproject, requested)
    assert len(found) == len(expected)
    for problem, fragment in zip(found, expected, strict=True):
        assert fragment in problem


def test_release_request_refuses_the_current_candidate() -> None:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    check = _load_request_check()
    assert check.main(["--candidate-sha", head, "--version", "0.1.0.dev0"]) == 1
    assert check.main(["--candidate-sha", "abc", "--version", "1.0.0"]) == 2


def test_owner_settings_cover_branch_tag_and_environment() -> None:
    settings = ROOT / "release" / "settings"
    protection = json.loads((settings / "branch-protection-main.json").read_text())
    required = {c["context"] for c in protection["required_status_checks"]["checks"]}
    ci_jobs = {
        job["name"] for job in _workflow("ci.yml")["jobs"].values() if "matrix" not in str(job)
    }
    assert {"Package and lint", "Protected container acceptance"} <= required
    assert {"Package and lint", "Protected container acceptance"} <= ci_jobs
    ruleset = json.loads((settings / "tag-ruleset.json").read_text())
    assert ruleset["conditions"]["ref_name"]["include"] == ["refs/tags/v*"]
    assert {r["type"] for r in ruleset["rules"]} >= {"creation", "update", "deletion"}
