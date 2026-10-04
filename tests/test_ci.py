import json
import subprocess

from actenon_airlock.cli import main, render
from actenon_airlock.manifest import discover


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def test_pr_cannot_approve_itself(project, monkeypatch, capsys):
    state = project('import requests\nrequests.post("https://example.com/a")\n')
    git(state.root, "init")
    git(state.root, "config", "user.email", "tests@example.invalid")
    git(state.root, "config", "user.name", "Airlock tests")
    git(
        state.root,
        "add",
        "main.py",
        ".airlock/approved.json",
        ".airlock/public-key.json",
        ".airlock/.gitignore",
    )
    git(state.root, "-c", "commit.gpgsign=false", "commit", "-m", "trusted baseline")
    baseline = git(state.root, "rev-parse", "HEAD")
    (state.root / "main.py").write_text(
        'import requests\nrequests.delete("https://example.com/b")\n'
    )
    state.approve(
        discover(state.root)
    )  # Even a valid current approval does not replace the trusted CI baseline.
    summary = state.root / "summary.md"
    output = state.root / "diff.json"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert (
        main(
            [
                "check",
                "--path",
                str(state.root),
                "--base",
                baseline,
                "--github",
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert json.loads(output.read_text())["added"][0]["action"] == "http.delete"
    assert "Airlock / Authority Review" in summary.read_text()
    assert "::error title=Airlock Authority Review" in capsys.readouterr().out
    (state.path / "public-key.json").write_text('{"key":"self-approved"}')
    assert main(["check", "--path", str(state.root), "--base", baseline]) == 2


def test_missing_trusted_baseline_fails(tmp_path):
    git(tmp_path, "init")
    (tmp_path / "main.py").write_text("print('hello')\n")
    assert main(["check", "--path", str(tmp_path), "--base", "HEAD", "--json"]) == 2


def test_source_strings_cannot_inject_github_workflow_commands():
    result = render(
        {
            "added": [
                {
                    "action": "http.post",
                    "resource": "x\n::error::injected",
                    "transport": "https://example.com",
                }
            ],
            "removed": [],
            "blocked": [],
            "parse_errors": [],
            "runtime_status": "BLOCKED",
        }
    )
    assert "\n::error" not in result
    assert "\\n::error" in result


def test_reapproval_preserves_command_and_bindings(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    args = ["init", "--path", str(tmp_path), "--approve"]
    assert (
        main(
            [
                *args,
                "--command",
                "main.py custom-argument",
                "--credential",
                "SERVICE_TOKEN=https://api.example.com",
            ]
        )
        == 0
    )
    assert main(args) == 0
    from actenon_airlock.state import State

    approved = State(tmp_path).approved()
    assert approved["command"] == ["main.py", "custom-argument"]
    assert approved["credential_bindings"] == {"SERVICE_TOKEN": "https://api.example.com"}


def test_pr_cannot_self_approve_model_expansion(project, capsys):
    state = project(
        "from openai import OpenAI\nOpenAI().chat.completions.create(model='first', messages=[])\n"
    )
    initial = {
        **discover(state.root),
        "protected_model": {"provider": "openai", "models": ["first"], "max_output_tokens": 100},
    }
    state.approve(initial)
    git(state.root, "init")
    git(state.root, "config", "user.email", "tests@example.invalid")
    git(state.root, "config", "user.name", "Airlock tests")
    git(state.root, "add", "main.py", ".airlock/approved.json", ".airlock/public-key.json")
    git(state.root, "-c", "commit.gpgsign=false", "commit", "-m", "trusted model constraint")
    baseline = git(state.root, "rev-parse", "HEAD")
    state.approve(
        {
            **initial,
            "protected_model": {
                **initial["protected_model"],
                "models": ["first", "unapproved"],
                "max_output_tokens": 200,
            },
        }
    )
    assert main(["check", "--path", str(state.root), "--base", baseline, "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["added"] == []
    assert result["model_constraints"]["expanded"]
