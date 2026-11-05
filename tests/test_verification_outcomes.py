"""Real-container verification: five honest outcomes per language, and a sandbox that holds.

Each language needs an image with its toolchain (CI sets the Python one; the Go and Node
images are optional). The sandbox probes run as ordinary project tests inside the real
verification container: a PASS there means every escape attempt was refused.
"""

import os
from pathlib import Path

import pytest

from actenon_airlock.cli import main
from actenon_airlock.state import State
from actenon_airlock.workflow import OUTCOMES, capture_candidate, verify_candidate

PY = os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE")
GO = os.environ.get("AIRLOCK_TEST_GO_IMAGE")
NODE = os.environ.get("AIRLOCK_TEST_NODE_IMAGE")
SETUP = ["--agent", "claude-code", "--model", "claude-test-model", "--max-run-usd", "1",
         "--price-per-mtok", "2,2.5,0.2,10", "--approve"]  # fmt: skip


def candidate(tmp_path, original: dict[str, str], changed: dict[str, str]):
    """A project as the person has it, and the agent's finished copy of it."""
    root = tmp_path / "project"
    for rel, text in original.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    assert main(["setup", "--path", str(root), *SETUP]) == 0
    state = State(root)
    run = state.local / "runs" / "finished"
    for rel, text in {**original, **changed}.items():
        (run / "workspace" / rel).parent.mkdir(parents=True, exist_ok=True)
        (run / "workspace" / rel).write_text(text)
    return state, capture_candidate(state, run)["candidate_sha256"]


def trusted(tmp_path, files: dict[str, str]) -> Path:
    path = tmp_path / "trusted"
    path.mkdir(exist_ok=True)
    for rel, text in files.items():
        (path / rel).write_text(text)
    return path


def outcome(state, sha, tests, image, **options):
    result = verify_candidate(state, sha, tests, image=image, **options)
    assert result["outcome"] == OUTCOMES[result["verdict"]]
    return result["outcome"], result


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------

PY_ORIGINAL = {"calc.py": "def add(a, b):\n    return a - b\n"}
PY_FIXED = {"calc.py": "def add(a, b):\n    return a + b\n"}
PY_TESTS = "from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"
PY_SKIP = "import pytest\n\n\n@pytest.mark.skip(reason='not here')\ndef test_later():\n    pass\n"


@pytest.mark.skipif(not PY, reason="requires the protected compute image")
@pytest.mark.parametrize(
    ("changed", "tests", "options", "expected"),
    [
        (PY_FIXED, {"test_calc.py": PY_TESTS}, {}, "PASS"),
        ({"calc.py": "def add(a, b):\n    return 0\n"}, {"test_calc.py": PY_TESTS}, {}, "FAIL"),
        (PY_FIXED, {"test_calc.py": PY_TESTS, "test_later.py": PY_SKIP}, {}, "SKIPPED"),
        (PY_FIXED, {"test_later.py": PY_SKIP}, {"accept_skips": True}, "SKIPPED"),
        (PY_FIXED, {"test_calc.py": PY_TESTS}, {"checks": [["no-such-tool"]]}, "UNSUPPORTED"),
        (PY_FIXED, {"README.txt": "no tests here\n"}, {}, "INCONCLUSIVE"),
    ],
    ids=["pass", "fail", "skipped", "all-skipped", "unsupported", "no-tests"],
)
def test_python_outcomes(tmp_path, changed, tests, options, expected):
    state, sha = candidate(tmp_path, PY_ORIGINAL, changed)
    got, result = outcome(state, sha, trusted(tmp_path, tests), PY, **options)
    assert got == expected, result


# --------------------------------------------------------------------------
# Go
# --------------------------------------------------------------------------

GO_ORIGINAL = {"go.mod": "module example.com/calc\n\ngo 1.21\n",
               "calc.go": "package calc\n\nfunc Add(a, b int) int { return a - b }\n"}  # fmt: skip
GO_FIXED = {"calc.go": "package calc\n\nfunc Add(a, b int) int { return a + b }\n"}
GO_TEST = ('package calc\n\nimport "testing"\n\nfunc TestAdd(t *testing.T) {\n'
           "\tif Add(2, 3) != 5 {\n\t\tt.Fatal(Add(2, 3))\n\t}\n}\n")  # fmt: skip
GO_SKIP = ('package calc\n\nimport "testing"\n\nfunc TestLater(t *testing.T) {\n'
           '\tt.Skip("not here")\n}\n')  # fmt: skip


@pytest.mark.parametrize(
    ("image_name", "changed", "tests", "expected"),
    [
        ("GO", GO_FIXED, {"calc_test.go": GO_TEST}, "PASS"),
        ("GO", {"calc.go": GO_ORIGINAL["calc.go"] + "\n// edit\n"}, {"calc_test.go": GO_TEST},
         "FAIL"),
        ("GO", GO_FIXED, {"calc_test.go": GO_TEST, "later_test.go": GO_SKIP}, "SKIPPED"),
        ("PY", GO_FIXED, {"calc_test.go": GO_TEST}, "UNSUPPORTED"),
        ("GO", GO_FIXED, {}, "INCONCLUSIVE"),
    ],
    ids=["pass", "fail", "skipped", "unsupported", "no-tests"],
)  # fmt: skip
def test_go_outcomes(tmp_path, image_name, changed, tests, expected):
    image = {"GO": GO, "PY": PY}[image_name]
    if not (GO and image):
        pytest.skip("requires a Go image (AIRLOCK_TEST_GO_IMAGE)")
    state, sha = candidate(tmp_path, GO_ORIGINAL, changed)
    got, result = outcome(state, sha, trusted(tmp_path, tests), image, profile="go")
    assert got == expected, result


# --------------------------------------------------------------------------
# TypeScript (vitest and tsc, as a typical project declares them)
# --------------------------------------------------------------------------

TS_ORIGINAL = {
    "package.json": '{"name": "calc", "type": "module", "devDependencies": '
    '{"typescript": "*", "vitest": "*"}}',
    "tsconfig.json": '{"compilerOptions": {"strict": true, "module": "NodeNext", '
    '"moduleResolution": "NodeNext", "target": "ES2022", "noEmit": true, '
    '"types": []}, "include": ["src"]}',
    "src/calc.ts": "export const add = (a: number, b: number): number => a - b;\n",
}
TS_FIXED = {"src/calc.ts": "export const add = (a: number, b: number): number => a + b;\n"}
TS_TEST = ('import { expect, it } from "vitest";\nimport { add } from "./calc.js";\n\n'
           'it("adds", () => expect(add(2, 3)).toBe(5));\n')  # fmt: skip
TS_SKIP = 'import { it } from "vitest";\n\nit.skip("later", () => {});\n'


@pytest.mark.parametrize(
    ("image_name", "changed", "tests", "options", "expected"),
    [
        ("NODE", TS_FIXED, {"src/calc.spec.ts": TS_TEST}, {}, "PASS"),
        ("NODE", {"src/calc.ts": "export const add = (a: number, b: number) => 0;\n"},
         {"src/calc.spec.ts": TS_TEST}, {}, "FAIL"),
        ("NODE", {"src/calc.ts": "export const add = (a: number, b: number): string => 'x';\n"},
         {"src/calc.spec.ts": TS_TEST}, {}, "FAIL"),
        ("NODE", TS_FIXED, {"src/calc.spec.ts": TS_TEST, "src/later.spec.ts": TS_SKIP}, {},
         "SKIPPED"),
        ("PY", TS_FIXED, {"src/calc.spec.ts": TS_TEST}, {}, "UNSUPPORTED"),
        ("NODE", {**TS_FIXED, "package.json": TS_ORIGINAL["package.json"].replace("calc", "c")},
         {"src/calc.spec.ts": TS_TEST}, {}, "INCONCLUSIVE"),
    ],
    ids=["pass", "fail", "type-error", "skipped", "unsupported", "agent-edited-config"],
)  # fmt: skip
def test_typescript_outcomes(tmp_path, image_name, changed, tests, options, expected):
    image = {"NODE": NODE, "PY": PY}[image_name]
    if not (NODE and image):
        pytest.skip("requires a Node image with vitest and typescript (AIRLOCK_TEST_NODE_IMAGE)")
    # The trusted spec lives under src/ so tsc and vitest find it beside the source.
    path = tmp_path / "trusted"
    for rel, text in tests.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_text(text)
    path.mkdir(exist_ok=True)
    state, sha = candidate(tmp_path, TS_ORIGINAL, changed)
    got, result = outcome(state, sha, path, image, profile="node", **options)
    assert got == expected, result


# --------------------------------------------------------------------------
# The sandbox holds against source-controlled tests
# --------------------------------------------------------------------------

PROBE = r"""
import os, pathlib, socket, subprocess

SECRET = os.environ.get("SUPERVISOR_SECRET_VALUE_MARKER", "")


def test_no_supervisor_credential_or_host_environment():
    for name, value in os.environ.items():
        assert "airlock-supervisor-secret" not in value, name
    assert not any(k in os.environ for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN"))


def test_no_docker_socket_and_no_host_home():
    for path in ("/var/run/docker.sock", "/run/docker.sock", "/Users", "/home/runner",
                 "/root/.docker"):
        assert not os.path.exists(path), path
    mounts = pathlib.Path("/proc/self/mountinfo").read_text()
    assert "docker.sock" not in mounts


def test_no_network_at_all():
    # --network none leaves the kernel's default tunnel devices listed, but down.
    up = [n for n in os.listdir("/sys/class/net")
          if n != "lo" and os.path.isfile(f"/sys/class/net/{n}/operstate")
          and pathlib.Path(f"/sys/class/net/{n}/operstate").read_text().strip() != "down"]

    assert up == [], up
    routes = pathlib.Path("/proc/net/route").read_text().splitlines()[1:]
    assert routes == [], routes
    for target in (("1.1.1.1", 443), ("192.168.65.254", 80)):
        with socket.socket() as s:
            s.settimeout(2)
            try:
                s.connect(target)
            except OSError:
                pass
            else:
                raise AssertionError(f"connected to {target}")
    try:
        socket.getaddrinfo("github.com", 443)
    except OSError:
        pass
    else:
        raise AssertionError("DNS resolved")


def test_unprivileged_with_no_capabilities():
    status = pathlib.Path("/proc/self/status").read_text()
    assert os.getuid() == 10000
    for field in ("CapEff", "CapPrm", "CapBnd"):
        line = next(l for l in status.splitlines() if l.startswith(field))
        assert int(line.split()[1], 16) == 0, line
    assert "NoNewPrivs:\t1" in status


def test_scripts_may_run_but_cannot_escalate_or_write_outside_scratch(tmp_path):
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh\nid -u\n")
    script.chmod(0o4755)  # setuid bit is ignored on a nosuid mount
    assert subprocess.run([str(script)], capture_output=True, text=True).stdout.strip() == "10000"
    for target in ("/candidate/x", "/trusted/x", "/settings/x", "/etc/x", "/usr/x"):
        try:
            pathlib.Path(target).write_text("x")
        except OSError:
            continue
        raise AssertionError(f"wrote {target}")
"""


@pytest.mark.skipif(not PY, reason="requires the protected compute image")
@pytest.mark.parametrize("path", ["pytest", "generic"])
def test_source_controlled_tests_cannot_escape_the_verification_sandbox(
    tmp_path, monkeypatch, path
):
    # A real-looking supervisor secret in the host environment must not reach the checks.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "airlock-supervisor-secret-must-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "airlock-supervisor-secret-must-not-leak")
    state, sha = candidate(tmp_path, PY_ORIGINAL, PY_FIXED)
    tests = trusted(tmp_path, {"test_probe.py": PROBE})
    options = {} if path == "pytest" else {
        "checks": [["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                    "--junitxml=/out/report-{index}.xml", "test_probe.py"]]
    }  # fmt: skip
    got, result = outcome(state, sha, tests, PY, **options)
    assert got == "PASS", [c["output_tail"] for c in result["checks"]]
    assert result["checks"][0]["counts"]["passed"] == 5
