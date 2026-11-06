"""The supported path from protected agent output to one reviewed consequence.

capture -> verify-candidate -> (operator approves exact bytes) -> publish -> reconcile.

Agent output is untrusted data: it is read with no symlink following and never
executed on this host. A passing test run is an observation, not approval. Only the
existing broker (Permit grant, Kernel claim, supervisor-held credential) dispatches.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .agents import TASK_FILE
from .common import AirlockError
from .github_consequence import MAX_CONTENT_BYTES
from .github_runtime import review_for, validate_profiles
from .manifest import discover
from .protected import (
    DEFAULT_IMAGE,
    EXCLUDED_INPUT,
    Docker,
    ProtectedBroker,
    _verify_container,
)
from .state import State

CANDIDATE_SCHEMA = "actenon-airlock/candidate/v1"
TESTS_PASSED = "TESTS_PASSED"
TESTS_FAILED = "TESTS_FAILED"
# Never staged for the agent, so their absence from a workspace is no change it made.
SKIP_NAMES = EXCLUDED_INPUT | {".home", ".tmp", ".gitignore", "airlock_agent.py", TASK_FILE}
MAX_JUNIT_BYTES = 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 32 * 1024 * 1024
MAX_CANDIDATE_TOTAL_BYTES = 256 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _observed(state: State, action: str, target: str, reason: str, **extra) -> dict:
    return state.receipt(
        {
            "id": "receipt_" + uuid4().hex,
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "target": target,
            "reason": reason,
            "decision": "OBSERVED",
            "credential_released": False,
            "execution_occurred": False,
            **extra,
        }
    )


def _tree(root: Path) -> dict[str, bytes]:
    """Regular files only. A link or special file refuses the whole tree."""
    found: dict[str, bytes] = {}
    total = 0

    def walk(directory: Path, prefix: str) -> None:
        nonlocal total
        for entry in sorted(os.scandir(directory), key=lambda e: e.name):
            if entry.name in SKIP_NAMES or entry.name.startswith((".aider", ".env")):
                continue
            # A newline in a name would let an agent forge lines of the reviewed diff.
            if not entry.name.isprintable():
                raise AirlockError("Candidate contains an unprintable file name")
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                walk(Path(entry.path), prefix + entry.name + "/")
            elif stat.S_ISREG(mode):
                size = entry.stat(follow_symlinks=False).st_size
                total += size
                if size > MAX_CANDIDATE_FILE_BYTES or total > MAX_CANDIDATE_TOTAL_BYTES:
                    raise AirlockError(f"Candidate exceeds its size bound at: {entry.name}")
                fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    found[prefix + entry.name] = stream.read()
            else:
                raise AirlockError(f"Candidate contains a link or special file: {entry.name}")

    walk(root, "")
    return found


def _candidate_dir(state: State, sha256: str) -> Path:
    if not _SHA256.fullmatch(sha256):
        raise AirlockError("Candidate ID must be a full SHA-256")
    path = state.local / "candidates" / sha256
    if not path.is_dir():
        raise AirlockError("Unknown candidate; run airlock capture first")
    return path


def _require_intact(candidate: Path, sha256: str) -> None:
    """The bytes tested and the bytes published must be the bytes captured."""
    if hashlib.sha256((candidate / "candidate.patch").read_bytes()).hexdigest() != sha256:
        raise AirlockError("Stored candidate bytes changed since capture")
    tree = _tree(candidate / "tree")
    for change in json.loads((candidate / "candidate.json").read_text())["changes"]:
        data = tree.get(change["path"])
        actual = hashlib.sha256(data).hexdigest() if data is not None else None
        if actual != change["after_sha256"]:
            raise AirlockError("Stored candidate bytes changed since capture")


def latest_run(state: State) -> Path:
    runs = state.local / "runs"
    finished = [p for p in runs.iterdir() if (p / "result.json").is_file()] if runs.is_dir() else []
    if not finished:
        raise AirlockError("No completed protected run to capture")
    return max(finished, key=lambda p: (p / "result.json").stat().st_mtime)


def capture_candidate(state: State, run: Path | None = None) -> dict:
    """Record the exact change an agent made, without trusting or executing it."""
    run = run or latest_run(state)
    before, after = _tree(state.root), _tree(run / "workspace")
    lines: list[str] = []
    changes = []
    for name in sorted(before.keys() | after.keys()):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        try:
            old_text = (old or b"").decode("utf-8")
            new_text = (new or b"").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AirlockError(f"Binary change is unsupported: {name}") from exc
        lines.extend(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile="a/" + name,
                tofile="b/" + name,
            )
        )
        changes.append(
            {
                "path": name,
                "status": "added" if old is None else "deleted" if new is None else "modified",
                "before_sha256": hashlib.sha256(old).hexdigest() if old is not None else None,
                "after_sha256": hashlib.sha256(new).hexdigest() if new is not None else None,
            }
        )
    if not changes:
        raise AirlockError("The run changed nothing; there is no candidate")
    patch = "".join(line if line.endswith("\n") else line + "\n" for line in lines).encode()
    if len(patch) > MAX_CONTENT_BYTES:
        raise AirlockError("Candidate exceeds the 64 KiB reviewed consequence bound")
    sha256 = hashlib.sha256(patch).hexdigest()
    destination = state.local / "candidates" / sha256
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    tree = destination / "tree"
    if not tree.exists():
        for name, data in after.items():
            target = tree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    (destination / "candidate.patch").write_bytes(patch)
    manifest = {
        "schema": CANDIDATE_SCHEMA,
        "candidate_sha256": sha256,
        "run": run.name,
        "changes": changes,
        "trust": "untrusted agent output",
    }
    (destination / "candidate.json").write_text(json.dumps(manifest, indent=2) + "\n")
    _observed(
        state,
        "candidate.capture",
        "candidate:" + sha256,
        "Exact agent output captured; nothing was executed, approved or published",
        stage="candidate-captured",
        candidate_sha256=sha256,
        run=run.name,
    )
    return manifest


def _tests_digest(tests: Path) -> str:
    digest = hashlib.sha256()
    for name, data in sorted(_tree(tests).items()):
        digest.update(name.encode() + b"\0" + hashlib.sha256(data).digest())
    return digest.hexdigest()


# Verdicts. Only TESTS_PASSED lets a candidate be published.
NO_TESTS_RAN = "NO_TESTS_RAN"  # the checks found nothing to run
PASSED_WITH_SKIPS = "PASSED_WITH_SKIPS"  # nothing failed, some tests skipped; not accepted
CONFIG_INCOMPATIBLE = "CONFIG_INCOMPATIBLE"  # the test tool refused its configuration
CONFIG_CHANGED = "CHECK_CONFIG_CHANGED_BY_AGENT"  # the agent edited what defines the checks
UNSUPPORTED = "UNSUPPORTED_REQUIREMENT"  # the image cannot run these checks
TIMED_OUT = "TIMED_OUT"
ALL_SKIPPED = "ALL_SKIPPED"  # every test that ran was skipped: nothing was checked

# Every verdict lands on one of five outcomes a person can act on.
OUTCOMES = {
    TESTS_PASSED: "PASS",
    TESTS_FAILED: "FAIL",
    PASSED_WITH_SKIPS: "SKIPPED",
    ALL_SKIPPED: "SKIPPED",
    UNSUPPORTED: "UNSUPPORTED",
    NO_TESTS_RAN: "INCONCLUSIVE",
    CONFIG_INCOMPATIBLE: "INCONCLUSIVE",
    CONFIG_CHANGED: "INCONCLUSIVE",
    TIMED_OUT: "INCONCLUSIVE",
}
# The PATH every check runs with, inside the verification container.
CHECK_PATH = (
    "/work/node_modules/.bin:/node_modules/.bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
)
# Where a check may write a JUnit report that Airlock then reads (index filled in).
JUNIT = "/out/report-{index}.xml"

# Fixed argument vectors: nothing here is shell text, and nothing comes from the candidate.
PROFILES = {
    "python": {
        "checks": [["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"]],
        "config": ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "conftest.py"),
    },
    "go": {
        "checks": [["go", "vet", "./..."], ["go", "test", "-json", "./..."]],
        "config": ("go.mod", "go.sum"),
    },
    "node": {
        "checks": [["npm", "test", "--silent"]],
        "config": ("package.json", "package-lock.json", "tsconfig.json", "vitest.config.ts",
                   "vitest.config.mts", "vitest.config.js", "jest.config.js", "jest.config.ts"),
    },
}  # fmt: skip
PYTEST_CONFIGS = ("pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg")


def node_checks(root: Path) -> list[list[str]]:
    """Node checks from the person's own package.json (never the candidate's)."""
    try:
        package = json.loads((root / "package.json").read_text())
    except (OSError, ValueError):
        package = {}
    tools = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
    checks = []
    if "typescript" in tools and (root / "tsconfig.json").is_file():
        checks.append(["tsc", "--noEmit", "-p", "tsconfig.json"])
    if "vitest" in tools:
        checks.append(["vitest", "run", "--reporter=junit", "--outputFile=" + JUNIT])
    return checks or [["npm", "test", "--silent"]]


def planned_checks(root: Path, profile: str, checks=None) -> list[list[str]]:
    """Exactly what verification will run: shown before it runs, recorded after."""
    if checks:
        commands = checks
    elif profile == "node":
        commands = node_checks(root)
    else:
        commands = PROFILES[profile]["checks"]
    return [[arg.replace("{index}", str(i)) for arg in c] for i, c in enumerate(commands)]


def detect_profile(root: Path) -> str:
    """The project's ecosystem, judged from the person's own project, never the candidate."""
    if (root / "go.mod").is_file():
        return "go"
    if (root / "package.json").is_file() and not (root / "pyproject.toml").is_file():
        return "node"
    return "python"


def _pytest_config(root: Path) -> Path | None:
    """The original project's pytest configuration, which the agent cannot have edited."""
    for name in PYTEST_CONFIGS:
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        text = path.read_text(errors="replace")
        if name == "pytest.ini" or (
            (name == "pyproject.toml" and "[tool.pytest.ini_options]" in text)
            or (name == "tox.ini" and "[pytest]" in text)
            or (name == "setup.cfg" and "[tool:pytest]" in text)
        ):
            return path
    return None


def _junit_counts(report: Path) -> dict | None:
    if not report.is_file() or report.is_symlink() or report.stat().st_size > MAX_JUNIT_BYTES:
        return None
    try:
        cases = list(ET.fromstring(report.read_bytes()).iter("testcase"))
    except ET.ParseError:
        return None

    def has(case, tag):
        return case.find(tag) is not None

    failed = sum(1 for c in cases if has(c, "failure") or has(c, "error"))
    skipped = sum(
        1 for c in cases if has(c, "skipped") and not (has(c, "failure") or has(c, "error"))
    )
    return {"tests": len(cases), "failed": failed, "skipped": skipped,
            "passed": len(cases) - failed - skipped}  # fmt: skip


def _go_counts(output: str) -> dict | None:
    """Per-test results from `go test -json` events; None when there are none."""
    final = {}
    for line in output.splitlines():
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("Test") and event.get("Action") in ("pass", "fail", "skip"):
            final[(event.get("Package"), event["Test"])] = event["Action"]
    if not final:
        return None
    values = list(final.values())
    return {"tests": len(values), "failed": values.count("fail"),
            "skipped": values.count("skip"), "passed": values.count("pass")}  # fmt: skip


def _count_verdict(counts: dict | None, accept_skips: bool = False) -> tuple[str, str]:
    if counts is None:
        return TESTS_FAILED, "no readable test report was produced"
    if not counts["tests"]:
        return NO_TESTS_RAN, "no tests ran"
    if counts["failed"]:
        return (
            TESTS_FAILED,
            f"{counts['failed']} of {counts['tests']} test{'s' if counts['tests'] != 1 else ''} failed",
        )
    if counts["skipped"] and not counts["passed"]:
        return ALL_SKIPPED, f"all {counts['tests']} tests were skipped, so nothing was checked"
    if counts["skipped"] and not accept_skips:
        return PASSED_WITH_SKIPS, (
            f"{counts['passed']} passed, {counts['skipped']} skipped; skips are not accepted "
            "unless you pass --accept-skips"
        )
    if counts["skipped"]:
        return TESTS_PASSED, f"{counts['passed']} passed, {counts['skipped']} skipped (accepted)"
    return TESTS_PASSED, f"{counts['tests']} test{'s' if counts['tests'] != 1 else ''} passed"


def _junit_verdict(report: Path, accept_skips: bool = False) -> tuple[str, str]:
    return _count_verdict(_junit_counts(report), accept_skips)


def _exit_verdict(code: int, label: str) -> tuple[str, str]:
    if code == 0:
        return TESTS_PASSED, f"{label}: passed"
    if code in (126, 127):
        return (
            UNSUPPORTED,
            f"{label}: the image cannot run it (exit {code}); pass --image with its toolchain",
        )
    if code == 124:
        return TIMED_OUT, f"{label}: timed out"
    return TESTS_FAILED, f"{label}: failed (exit {code})"


def verify_candidate(
    state: State,
    sha256: str,
    tests: Path,
    *,
    image=DEFAULT_IMAGE,
    profile: str = "auto",
    checks: list[list[str]] | None = None,
    accept_skips: bool = False,
    allow_config_change: bool = False,
) -> dict:
    """Run operator-held checks against the candidate in an inspected no-network container.

    The candidate shares the test interpreter, so it can alter behaviour under test or
    forge a report. TESTS_PASSED means the specified checks passed with it in place; it
    is not a correctness or safety finding and it approves nothing.

    Python runs pytest over the trusted tests with the ORIGINAL project's pytest
    configuration (never the candidate's). Go and Node run fixed commands on a private
    copy of the candidate with the trusted files laid over it. If the candidate changed a
    file that defines the checks, the result is CHECK_CONFIG_CHANGED_BY_AGENT unless the
    operator allows it, and that permission is recorded.
    """
    candidate = _candidate_dir(state, sha256)
    _require_intact(candidate, sha256)
    if not tests.is_dir():
        raise AirlockError("Trusted tests directory does not exist")
    if tests.resolve().is_relative_to(state.root.resolve()):
        raise AirlockError("Trusted tests must be held outside the project the agent worked on")
    profile = detect_profile(state.root) if profile == "auto" else profile
    if profile not in PROFILES:
        raise AirlockError(f"Unknown verification profile {profile!r}: use python, go or node")
    commands = planned_checks(state.root, profile, checks)
    if any(not c or not all(isinstance(a, str) and a for a in c) for c in commands):
        raise AirlockError("Each check must be a non-empty command")
    tests_sha256 = _tests_digest(tests)
    manifest = json.loads((candidate / "candidate.json").read_text())
    changed_config = sorted(
        c["path"] for c in manifest["changes"]
        if Path(c["path"]).name in PROFILES[profile]["config"]
    )  # fmt: skip
    config = _pytest_config(state.root) if profile == "python" else None
    docker = Docker()
    docker.verify_engine()
    resolved = docker.image(image)
    results = []
    with tempfile.TemporaryDirectory(prefix="airlock-verify-") as temporary:
        root = Path(temporary).resolve()
        source, trusted, output = root / "candidate", root / "trusted", root / "out"
        shutil.copytree(candidate / "tree", source)
        shutil.copytree(tests, trusted, ignore=shutil.ignore_patterns("__pycache__"))
        settings = root / "settings"
        settings.mkdir()
        if config is not None:
            shutil.copyfile(config, settings / config.name)
        output.mkdir()
        for path in [root, source, trusted, settings, *source.rglob("*"), *trusted.rglob("*"),
                     *settings.rglob("*")]:  # fmt: skip
            path.chmod(0o755 if path.is_dir() else 0o644)
        output.chmod(0o777)
        mounts = {
            "/candidate": {"rw": False, "type": "bind", "source": str(source)},
            "/trusted": {"rw": False, "type": "bind", "source": str(trusted)},
            "/settings": {"rw": False, "type": "bind", "source": str(settings)},
            "/out": {"rw": True, "type": "bind", "source": str(output)},
        }
        base = [
            "create", "--pull", "never", "--network", "none", "--read-only",
            "--no-healthcheck", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--ipc", "private",
            "--pids-limit", "128", "--memory", "1g", "--cpus", "2",
            "--user", "10000:10000",
            # Executable scratch space (Docker's tmpfs default is noexec): tests may run
            # helper scripts they create, and the container already has no network, no
            # credentials and no capabilities. /work belongs to the unprivileged checker.
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
            "--tmpfs", "/work:rw,exec,nosuid,nodev,size=1g,uid=10000,gid=10000,mode=0700",
            "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONPATH=/candidate/src:/candidate",
            "--env", "HOME=/tmp", "--env", "CI=1", "--env", "NO_COLOR=1",
            "--env", "GOCACHE=/work/.go-cache", "--env", "GOFLAGS=-mod=mod",
            "--env", "GOPROXY=off", "--env", "GOTOOLCHAIN=local",
            "--env", "PATH=" + CHECK_PATH,
            *[a for target, m in mounts.items()
              for a in ("--mount", f"type=bind,source={m['source']},target={target}"
                                   + (",readonly" if not m["rw"] else ""))],
        ]  # fmt: skip
        for index, command in enumerate(commands):
            label = " ".join(command)
            if profile == "python" and checks is None:
                settings_arg = f"/settings/{config.name}" if config is not None else "/dev/null"
                argv = ["--workdir", "/candidate", "--entrypoint", command[0], resolved["Id"],
                        *command[1:], "-c", settings_arg, "--rootdir", "/trusted",
                        "--confcutdir", "/trusted", f"--junitxml=/out/report-{index}.xml",
                        "/trusted"]  # fmt: skip
            else:
                argv = ["--workdir", "/work", "--entrypoint", "sh", resolved["Id"], "-c",
                        'cp -R /candidate/. /work/ && cp -R /trusted/. /work/ && exec "$@"',
                        "sh", *command]  # fmt: skip
            identity = None
            try:
                identity = docker.call([*base, *argv])
                _verify_container(docker, identity, agent=True, mounts=mounts)
                try:
                    subprocess.run(
                        [docker.binary, "start", "-a", identity],
                        capture_output=True, timeout=600, env=docker.environment,
                    )  # fmt: skip
                    exit_code = docker.json(["inspect", identity])[0]["State"]["ExitCode"]
                except subprocess.TimeoutExpired:
                    exit_code = 124
                # Local only, for the person reading the result; never put in a receipt.
                logs = subprocess.run(
                    [docker.binary, "logs", identity],
                    capture_output=True, text=True, timeout=60, env=docker.environment,
                )  # fmt: skip
                full = logs.stdout[-8 * 1024 * 1024 :]
                tail = [line for line in (logs.stdout + logs.stderr).splitlines()
                        if line.strip() and not line.startswith('{"Time"')]  # fmt: skip
            finally:
                if identity:
                    docker.call(["rm", "-f", identity])
            if profile == "python" and checks is None:
                verdict, detail = _junit_verdict(output / f"report-{index}.xml", accept_skips)
                if exit_code in (3, 4):
                    verdict, detail = (
                        CONFIG_INCOMPATIBLE,
                        (f"pytest could not use the project's configuration (exit {exit_code})"),
                    )
                elif exit_code == 5:
                    verdict, detail = NO_TESTS_RAN, "pytest collected no tests"
                elif exit_code == 124:
                    verdict, detail = TIMED_OUT, "the tests timed out"
                elif exit_code not in (0, 1) or (exit_code == 1 and verdict == TESTS_PASSED):
                    verdict, detail = TESTS_FAILED, f"pytest exited {exit_code}: {detail}"
                counts = _junit_counts(output / f"report-{index}.xml")
            else:
                verdict, detail = _exit_verdict(exit_code, label)
                counts = None
                if verdict in (TESTS_PASSED, TESTS_FAILED):
                    # A per-test report, when the check produced one, decides skips too.
                    counts = _junit_counts(output / f"report-{index}.xml")
                    if counts is None and "-json" in command and command[:2] == ["go", "test"]:
                        # No per-test events at all: nothing was tested, whatever the exit.
                        counts = _go_counts(full) or {"tests": 0, "failed": 0,
                                                       "skipped": 0, "passed": 0}  # fmt: skip
                        if exit_code != 0 and not counts["tests"]:
                            counts = None  # a build failure: keep the failed exit
                    if counts is not None:
                        counted, why = _count_verdict(counts, accept_skips)
                        if not (exit_code != 0 and counted == TESTS_PASSED):
                            verdict, detail = counted, f"{label}: {why}"
                        else:
                            detail = f"{label}: failed (exit {exit_code}) though no test failed"
            results.append(
                {"check": command, "exit": exit_code, "verdict": verdict,
                 "outcome": OUTCOMES[verdict], "detail": detail, "counts": counts,
                 "output_tail": tail[-15:]}
            )  # fmt: skip
    failing = [r for r in results if r["verdict"] != TESTS_PASSED]
    verdict, detail = (
        (failing[0]["verdict"], failing[0]["detail"]) if failing
        else (TESTS_PASSED, "; ".join(r["detail"] for r in results))
    )  # fmt: skip
    if changed_config and not allow_config_change and verdict == TESTS_PASSED:
        verdict = CONFIG_CHANGED
        detail = (
            f"the checks passed, but the agent changed {', '.join(changed_config)}, which "
            "defines them; review it and rerun with --allow-config-change to accept it"
        )
    receipt = _observed(
        state,
        "candidate.verify",
        "candidate:" + sha256,
        detail,
        stage="candidate-tests",
        candidate_sha256=sha256,
        tests_sha256=tests_sha256,
        image_id=resolved["Id"],
        verdict=verdict,
        outcome=OUTCOMES[verdict],
        profile=profile,
        checks=[" ".join(c) for c in commands],
        project_test_config=config.name if config is not None else None,
        agent_changed_check_config=changed_config,
        config_change_allowed=bool(changed_config and allow_config_change),
        skips_accepted=bool(accept_skips),
        meaning="specified tests with the candidate imported; not safety, not approval",
    )
    return {
        "verdict": verdict,
        "outcome": OUTCOMES[verdict],
        "detail": detail,
        "profile": profile,
        "checks": results,
        "agent_changed_check_config": changed_config,
        "candidate_sha256": sha256,
        "tests_sha256": tests_sha256,
        "image_id": resolved["Id"],
        "receipt_id": receipt["id"],
    }


def _latest_verification(state: State, sha256: str) -> dict | None:
    journal = state.verify_receipts()
    if not journal["ok"]:
        raise AirlockError("Receipt journal is invalid; refusing to publish")
    rows = [
        item["row"]
        for item in journal["rows"]
        if item["row"].get("stage") == "candidate-tests"
        and item["row"].get("candidate_sha256") == sha256
    ]
    return rows[-1] if rows else None


def publish_candidate(state: State, sha256: str, *, client=None) -> dict:
    """Dispatch one exact approved creation through the broker; never claim the outcome.

    `client` is a trusted host seam for the synthetic provider, never agent input.
    """
    candidate = _candidate_dir(state, sha256)
    _require_intact(candidate, sha256)
    patch = (candidate / "candidate.patch").read_bytes()
    verification = _latest_verification(state, sha256)
    if verification is None or verification["verdict"] != TESTS_PASSED:
        raise AirlockError(
            "Publication policy requires a passing verification of this exact candidate"
        )
    approved = state.approved()
    profiles = validate_profiles(approved.get("protected_github", []))
    matching = [p for p in profiles if review_for(p).content_sha256 == sha256]
    if not matching:
        raise AirlockError(
            "No separately approved GitHub creation names this exact candidate; passing "
            "tests do not authorize publication"
        )
    review = review_for(matching[0])
    body = json.dumps(
        {
            "branch": review.branch,
            "message": review.message,
            "content": base64.b64encode(patch).decode(),
        }
    ).encode()
    broker = ProtectedBroker(state, discover(state.root), approved.get("credential_bindings", {}))
    if client is not None:
        broker.http.close()
        broker.http = client
    try:
        result = broker.handle(
            {
                "kind": "protected-http",
                "method": "PUT",
                "url": review.contents_url,
                "headers": {},
                "body": base64.b64encode(body).decode(),
            }
        )
    finally:
        broker.close()
    # The transport reply omits the effect after a lost acknowledgement. The signed
    # receipt records whether a request left, so a held dispatch never reads as refused.
    receipt = next(
        (
            item["row"]
            for item in state.verify_receipts()["rows"]
            if item["row"].get("id") == result.get("receipt_id")
        ),
        {},
    )
    outcome = receipt.get("outcome")
    if result.get("ok"):
        status = "DISPATCHED_UNCONFIRMED"
    elif receipt.get("execution_attempted"):
        status = "AMBIGUOUS"
    else:
        status = "REFUSED"
    return {
        "status": status,
        "outcome": outcome,
        "effect_id": receipt.get("effect_id"),
        "reason": result.get("reason"),
        "receipt_id": result.get("receipt_id"),
        "target": review.contents_url,
    }


def status(state: State, since: int = 0) -> dict:
    """What happened, kept separate from what is known about the outside world.

    `since` limits the activity counts to receipts after that position, for one run.
    """
    from .evidence import load_public_key, verify_offline

    public = load_public_key(str(state.path / "public-key.json"))
    journal = state.receipts_path.read_bytes() if state.receipts_path.exists() else b""
    report = verify_offline(journal, public)
    rows = [json.loads(line) for line in journal.splitlines()] if report["integrity"]["ok"] else []
    rows = rows[since:]
    refused = [r for r in rows if r.get("decision") == "DENY"]
    calls = [r for r in rows if "inference_invocation" in r]
    answered = [r for r in calls if r.get("stage") == "response-received"]
    confirmed = sum(r.get("outcome") == "COMMITTED" for r in answered)
    unconfirmed = len(answered) - confirmed
    unconfirmed += sum(r.get("stage") == "execution-error" for r in calls)
    settled = [r for r in calls if r.get("stage") in {"response-received", "execution-error"}]
    return {
        "emergency_stop": state.emergency_stop(),
        "integrity_ok": report["integrity"]["ok"],
        "receipts": report["integrity"]["receipts"],
        "completeness": report["completeness"]["status"],
        "refused": len(refused),
        "refusal_reasons": sorted({r.get("reason", "") for r in refused})[:8],
        "independently_observed": report["provider_truth"]["independently_observed"],
        "runtime_claims": report["provider_truth"]["runtime_claims"],
        "unresolved_effects": report["provider_truth"]["unresolved_ambiguous"],
        "inference": {
            "dispatched": confirmed + unconfirmed,
            "confirmed": confirmed,
            "unconfirmed": unconfirmed,
            "retries_held": sum(
                r.get("decision") == "DENY" and r["inference_retry"] for r in calls
            ),
        },
        "model_spend": {
            "estimated_microusd": sum(r.get("inference_cost_microusd", 0) for r in settled),
            "declined_calls": sum(bool(r.get("inference_declined")) for r in settled),
        },
    }
