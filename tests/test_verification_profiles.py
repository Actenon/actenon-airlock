"""Reviewed verification profiles: honest verdicts across Python, Go and Node projects."""

import os
from pathlib import Path

import pytest

from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.state import State
from actenon_airlock.workflow import (
    ALL_SKIPPED,
    CONFIG_CHANGED,
    NO_TESTS_RAN,
    PASSED_WITH_SKIPS,
    TESTS_FAILED,
    TESTS_PASSED,
    UNSUPPORTED,
    _exit_verdict,
    _junit_verdict,
    _pytest_config,
    capture_candidate,
    detect_profile,
    verify_candidate,
)

SETUP = ["--agent", "claude-code", "--model", "claude-test-model", "--max-run-usd", "1",
         "--price-per-mtok", "2,2.5,0.2,10", "--approve"]  # fmt: skip


def junit(tmp_path, cases):
    body = "".join(f'<testcase name="t{i}">{inner}</testcase>' for i, inner in enumerate(cases))
    path = tmp_path / "report.xml"
    path.write_text(f"<testsuites><testsuite>{body}</testsuite></testsuites>")
    return path


def test_verdicts_separate_failure_skips_and_nothing_run(tmp_path):
    assert _junit_verdict(junit(tmp_path, ["", ""]))[0] == TESTS_PASSED
    assert _junit_verdict(junit(tmp_path, ["", "<failure/>"]))[0] == TESTS_FAILED
    assert _junit_verdict(junit(tmp_path, ["", "<error/>"]))[0] == TESTS_FAILED
    skipped = junit(tmp_path, ["", "<skipped/>"])
    assert _junit_verdict(skipped)[0] == PASSED_WITH_SKIPS
    verdict, detail = _junit_verdict(skipped, accept_skips=True)
    assert verdict == TESTS_PASSED and "1 skipped (accepted)" in detail
    # Skips alone never pass, accepted or not: something must actually have been tested.
    assert _junit_verdict(junit(tmp_path, ["<skipped/>"]), accept_skips=True)[0] == ALL_SKIPPED
    assert _junit_verdict(junit(tmp_path, []))[0] == NO_TESTS_RAN
    assert _junit_verdict(tmp_path / "missing.xml")[0] == TESTS_FAILED


def test_a_missing_toolchain_is_reported_as_unsupported_not_as_a_test_failure():
    assert _exit_verdict(0, "go test ./...")[0] == TESTS_PASSED
    assert _exit_verdict(127, "go test ./...")[0] == UNSUPPORTED
    assert "--image" in _exit_verdict(127, "go test ./...")[1]
    assert _exit_verdict(1, "go test ./...")[0] == TESTS_FAILED


def test_the_profile_and_pytest_config_come_from_your_project(tmp_path):
    assert detect_profile(tmp_path) == "python"
    (tmp_path / "go.mod").write_text("module example\n")
    assert detect_profile(tmp_path) == "go"
    (tmp_path / "go.mod").unlink()
    (tmp_path / "package.json").write_text("{}")
    assert detect_profile(tmp_path) == "node"
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    assert detect_profile(tmp_path) == "python"
    assert _pytest_config(tmp_path) is None  # no [tool.pytest.ini_options]
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\naddopts='-q'\n")
    assert _pytest_config(tmp_path) == tmp_path / "pyproject.toml"


# --------------------------------------------------------------------------
# End to end, in the real contained container (CI's container job sets the image)
# --------------------------------------------------------------------------

IMAGE = os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE")
needs_image = pytest.mark.skipif(not IMAGE, reason="requires a local protected image")

PYPROJECT = """[tool.pytest.ini_options]
filterwarnings = ["error"]
markers = ["slow: deselected by default"]
addopts = "-m 'not slow'"
"""
TESTS = """import pathlib, subprocess, sys
import pytest
from pkg.calc import add


def test_add():
    assert add(2, 3) == 5


@pytest.mark.slow
def test_deselected_by_the_project_config():
    raise AssertionError("must not run")


@pytest.mark.skipif(sys.platform != "win32", reason="windows only")
def test_windows_only():
    pass


def test_runs_a_helper_script_it_writes(tmp_path):
    script = tmp_path / "helper.sh"
    script.write_text("#!/bin/sh\\necho ok\\n")
    script.chmod(0o755)
    assert subprocess.run([str(script)], capture_output=True, text=True).stdout == "ok\\n"
"""


def candidate(tmp_path: Path, files: dict[str, str]) -> tuple[State, str]:
    root = tmp_path / "project"
    (root / "src/pkg").mkdir(parents=True)
    (root / "src/pkg/__init__.py").write_text("")
    (root / "src/pkg/calc.py").write_text("def add(a, b):\n    return a - b\n")
    (root / "pyproject.toml").write_text(PYPROJECT)
    assert main(["setup", "--path", str(root), *SETUP]) == 0
    state = State(root)
    run = state.local / "runs" / "finished"
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if rel.parts[0] in {".airlock", "airlock_agent.py"} or path.is_dir():
            continue
        (run / "workspace" / rel).parent.mkdir(parents=True, exist_ok=True)
        (run / "workspace" / rel).write_bytes(path.read_bytes())
    for rel, text in files.items():
        (run / "workspace" / rel).write_text(text)
    return state, capture_candidate(state, run)["candidate_sha256"]


@needs_image
def test_python_uses_the_project_config_src_layout_and_reports_skips(tmp_path):
    state, sha = candidate(tmp_path, {"src/pkg/calc.py": "def add(a, b):\n    return a + b\n"})
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "test_calc.py").write_text(TESTS)
    result = verify_candidate(state, sha, trusted, image=IMAGE, profile="python")
    assert result["verdict"] == PASSED_WITH_SKIPS, result
    assert result["checks"][0]["counts"] == {"tests": 3, "failed": 0, "skipped": 1, "passed": 2}
    accepted = verify_candidate(state, sha, trusted, image=IMAGE, profile="python",
                                accept_skips=True)  # fmt: skip
    assert accepted["verdict"] == TESTS_PASSED
    receipt = [r["row"] for r in state.verify_receipts()["rows"]
               if r["row"].get("receipt_id", r["row"].get("id")) == accepted["receipt_id"]]  # fmt: skip
    assert receipt and receipt[0]["skips_accepted"] is True
    assert receipt[0]["project_test_config"] == "pyproject.toml"


@needs_image
def test_a_wrong_change_fails_and_an_edited_test_config_is_never_silently_trusted(tmp_path):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "test_calc.py").write_text(TESTS)
    state, wrong = candidate(tmp_path, {"src/pkg/calc.py": "def add(a, b):\n    return 0\n"})
    assert verify_candidate(state, wrong, trusted, image=IMAGE, accept_skips=True)["verdict"] == (
        TESTS_FAILED
    )
    # The agent fixes the code but also rewrites the config to deselect everything.
    sneaky = PYPROJECT.replace("-m 'not slow'", "-k nothing")
    state2, sha = candidate(
        tmp_path / "second",
        {"src/pkg/calc.py": "def add(a, b):\n    return a + b\n", "pyproject.toml": sneaky},
    )
    result = verify_candidate(state2, sha, trusted, image=IMAGE, accept_skips=True)
    # The project's original config is what ran, and the agent's edit is surfaced.
    assert result["checks"][0]["counts"]["passed"] == 2
    assert result["verdict"] == CONFIG_CHANGED
    assert result["agent_changed_check_config"] == ["pyproject.toml"]
    allowed = verify_candidate(state2, sha, trusted, image=IMAGE, accept_skips=True,
                               allow_config_change=True)  # fmt: skip
    assert allowed["verdict"] == TESTS_PASSED


def test_trusted_tests_must_live_outside_the_project(tmp_path):
    state, sha = candidate(tmp_path, {"src/pkg/calc.py": "def add(a, b):\n    return a + b\n"})
    with pytest.raises(AirlockError, match="outside the project"):
        verify_candidate(state, sha, state.root, image="unused")
    with pytest.raises(AirlockError, match="Unknown verification profile"):
        verify_candidate(state, sha, tmp_path, image="unused", profile="cobol")


GO_IMAGE = os.environ.get("AIRLOCK_TEST_GO_IMAGE")
NODE_IMAGE = os.environ.get("AIRLOCK_TEST_NODE_IMAGE")


@pytest.mark.skipif(not GO_IMAGE, reason="requires an image with a Go toolchain")
def test_go_runs_vet_and_tests_over_a_private_copy(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "go.mod").write_text("module example.com/calc\n\ngo 1.21\n")
    (root / "calc.go").write_text("package calc\n\nfunc Add(a, b int) int { return a - b }\n")
    assert main(["setup", "--path", str(root), *SETUP]) == 0
    state = State(root)
    run = state.local / "runs" / "finished" / "workspace"
    run.mkdir(parents=True)
    (run / "go.mod").write_text((root / "go.mod").read_text())
    (run / "calc.go").write_text("package calc\n\nfunc Add(a, b int) int { return a + b }\n")
    sha = capture_candidate(state, run.parent)["candidate_sha256"]
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "calc_test.go").write_text(
        'package calc\n\nimport "testing"\n\nfunc TestAdd(t *testing.T) {\n'
        "\tif Add(2, 3) != 5 {\n\t\tt.Fatal(Add(2, 3))\n\t}\n}\n"
    )
    result = verify_candidate(state, sha, trusted, image=GO_IMAGE)
    assert result["profile"] == "go" and result["verdict"] == TESTS_PASSED, result
    assert [r["check"] for r in result["checks"]] == [
        ["go", "vet", "./..."],
        ["go", "test", "-json", "./..."],
    ]


@pytest.mark.skipif(not NODE_IMAGE, reason="requires an image with Node")
def test_node_runs_the_reviewed_command_not_the_agents_script(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text('{"name": "calc", "scripts": {"test": "node test.js"}}')
    (root / "calc.js").write_text("exports.add = (a, b) => a - b;\n")
    assert main(["setup", "--path", str(root), *SETUP]) == 0
    state = State(root)
    run = state.local / "runs" / "finished" / "workspace"
    run.mkdir(parents=True)
    # Wrong code, and the agent "fixes" the test script to always pass.
    (run / "package.json").write_text('{"name": "calc", "scripts": {"test": "true"}}')
    (run / "calc.js").write_text("exports.add = (a, b) => 0;\n")
    sha = capture_candidate(state, run.parent)["candidate_sha256"]
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "test.js").write_text(
        "const {add} = require('./calc'); if (add(2, 3) !== 5) { process.exit(1); }\n"
    )
    result = verify_candidate(state, sha, trusted, image=NODE_IMAGE,
                              checks=[["node", "test.js"]])  # fmt: skip
    assert result["verdict"] == TESTS_FAILED, result
    default = verify_candidate(state, sha, trusted, image=NODE_IMAGE)
    # npm test would run the agent's "true"; the edited package.json is surfaced instead.
    assert default["verdict"] == CONFIG_CHANGED
