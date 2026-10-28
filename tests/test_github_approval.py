import copy
import json
import subprocess

import pytest

from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.github_runtime import PROFILE_SCHEMA
from actenon_airlock.manifest import authority_diff, discover
from actenon_airlock.state import State


def profile():
    return {
        "schema": PROFILE_SCHEMA,
        "exclusive_writer": True,
        "credential_name": "GITHUB_TOKEN",
        "review": {
            "repo_id": 123,
            "repo_node_id": "R_fixture",
            "owner": "acme",
            "repo": "disposable",
            "branch": "review",
            "path": "patches/fix.patch",
            "message": "reviewed patch",
            "content_sha256": "a" * 64,
            "expected_parent_sha": "b" * 40,
        },
    }


def source(root):
    (root / "agent.py").write_text(
        "import requests\nrequests.put('https://api.github.com/repos/acme/disposable/contents/patches/fix.patch')\n"
    )


def test_profile_proposal_requires_separate_explicit_approval(tmp_path):
    source(tmp_path)
    path = tmp_path / "review.json"
    path.write_text(json.dumps(profile()))
    args = ["init", "--path", str(tmp_path), "--github-create", str(path)]
    assert main(args) == 0
    state = State(tmp_path)
    with pytest.raises(AirlockError, match="No local approval"):
        state.approved()
    assert json.loads((state.path / "proposed.json").read_text())["protected_github"] == [profile()]
    assert main([*args, "--approve"]) == 0
    assert state.approved()["protected_github"] == [profile()]
    assert main(["init", "--path", str(tmp_path), "--clear-github", "--approve"]) == 0
    assert state.approved()["protected_github"] == []


@pytest.mark.parametrize(
    "change",
    [
        {"exclusive_writer": False},
        {"credential_name": "ARBITRARY_SECRET"},
        {"extra": "ignored?"},
    ],
)
def test_unsupported_profile_never_becomes_authority(tmp_path, change):
    source(tmp_path)
    path = tmp_path / "review.json"
    path.write_text(json.dumps({**profile(), **change}))
    assert main(["init", "--path", str(tmp_path), "--github-create", str(path), "--approve"]) == 2
    assert not (tmp_path / ".airlock/approved.json").exists()


def test_pr_cannot_self_approve_exact_github_consequence(tmp_path, capsys):
    source(tmp_path)
    state = State(tmp_path)
    current = discover(tmp_path, env={})
    state.approve({**current, "protected_github": []})

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init")
    git("config", "user.email", "tests@example.invalid")
    git("config", "user.name", "Airlock tests")
    git("add", "agent.py", ".airlock/approved.json", ".airlock/public-key.json")
    git("-c", "commit.gpgsign=false", "commit", "-m", "trusted baseline")
    baseline = git("rev-parse", "HEAD")
    state.approve({**current, "protected_github": [profile()]})
    assert main(["check", "--path", str(tmp_path), "--base", baseline, "--json"]) == 2
    value = json.loads(capsys.readouterr().out)
    assert value["added"] == []
    assert value["github_constraints"]["expanded"]
    assert value["runtime_status"] == "BLOCKED UNTIL APPROVED"


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("content_sha256", "c" * 64),
        ("path", "patches/other.patch"),
        ("branch", "other"),
        ("expected_parent_sha", "d" * 40),
        ("message", "new message"),
    ],
)
def test_reviewed_parameter_changes_require_review(field, replacement):
    initial = {"powers": [], "protected_github": [profile()]}
    changed = copy.deepcopy(initial)
    changed["protected_github"][0]["review"][field] = replacement
    assert authority_diff(initial, changed)["github_constraints"]["expanded"]
    assert not authority_diff(initial, {"powers": [], "protected_github": []})[
        "github_constraints"
    ]["expanded"]


@pytest.mark.parametrize("invalid", [None, {}, "unexpected", [None], [{"review": {}}]])
def test_invalid_profile_is_a_blocking_ci_difference(invalid):
    result = authority_diff({"powers": []}, {"powers": [], "protected_github": invalid})
    assert result["github_constraints"]["expanded"]
    assert result["runtime_status"] == "BLOCKED UNTIL APPROVED"
