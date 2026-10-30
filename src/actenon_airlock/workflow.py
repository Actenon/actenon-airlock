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

from .common import AirlockError
from .github_consequence import MAX_CONTENT_BYTES
from .github_runtime import review_for, validate_profiles
from .manifest import EXCLUDED, discover
from .protected import DEFAULT_IMAGE, Docker, ProtectedBroker, _verify_container
from .state import State

CANDIDATE_SCHEMA = "actenon-airlock/candidate/v1"
TESTS_PASSED = "TESTS_PASSED"
TESTS_FAILED = "TESTS_FAILED"
SKIP_NAMES = EXCLUDED | {".home", ".tmp", ".gitignore", "airlock_agent.py"}
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


def _junit_verdict(report: Path) -> tuple[str, str]:
    if not report.is_file() or report.is_symlink():
        return TESTS_FAILED, "no test report was produced"
    if report.stat().st_size > MAX_JUNIT_BYTES:
        return TESTS_FAILED, "test report exceeds the supported size"
    try:
        cases = list(ET.fromstring(report.read_bytes()).iter("testcase"))
    except ET.ParseError:
        return TESTS_FAILED, "test report is malformed"
    if not cases:
        return TESTS_FAILED, "no tests ran"
    bad = [
        c for c in cases if any(c.find(tag) is not None for tag in ("failure", "error", "skipped"))
    ]
    if bad:
        return TESTS_FAILED, f"{len(bad)} of {len(cases)} tests did not pass"
    return TESTS_PASSED, f"{len(cases)} tests passed"


def verify_candidate(state: State, sha256: str, tests: Path, *, image=DEFAULT_IMAGE) -> dict:
    """Run operator-held tests against the candidate in an inspected no-network container.

    The candidate shares the test interpreter, so it can alter behaviour under test
    or forge a report. TESTS_PASSED means specified tests passed with it imported;
    it is not a correctness or safety finding and it approves nothing.
    """
    candidate = _candidate_dir(state, sha256)
    _require_intact(candidate, sha256)
    if not tests.is_dir():
        raise AirlockError("Trusted tests directory does not exist")
    if tests.resolve().is_relative_to(state.root.resolve()):
        raise AirlockError("Trusted tests must be held outside the project the agent worked on")
    tests_sha256 = _tests_digest(tests)
    docker = Docker()
    docker.verify_engine()
    resolved = docker.image(image)
    identity = None
    with tempfile.TemporaryDirectory(prefix="airlock-verify-") as temporary:
        root = Path(temporary).resolve()
        source, trusted, output = root / "candidate", root / "trusted", root / "out"
        shutil.copytree(candidate / "tree", source)
        shutil.copytree(tests, trusted, ignore=shutil.ignore_patterns("__pycache__"))
        output.mkdir()
        for path in [root, source, trusted, *source.rglob("*"), *trusted.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        output.chmod(0o777)
        try:
            identity = docker.call(
                [
                    "create", "--pull", "never", "--network", "none", "--read-only",
                    "--no-healthcheck", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--ipc", "private",
                    "--pids-limit", "128", "--memory", "1g", "--cpus", "2",
                    "--user", "10000:10000", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
                    "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONPATH=/candidate",
                    "--env", "HOME=/tmp", "--workdir", "/tmp",
                    "--mount", f"type=bind,source={source},target=/candidate,readonly",
                    "--mount", f"type=bind,source={trusted},target=/trusted,readonly",
                    "--mount", f"type=bind,source={output},target=/out",
                    "--entrypoint", "python3", resolved["Id"],
                    "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", "/dev/null",
                    "--rootdir", "/trusted", "--confcutdir", "/trusted",
                    "--junitxml=/out/report.xml", "/trusted",
                ]
            )  # fmt: skip
            _verify_container(
                docker,
                identity,
                agent=True,
                mounts={
                    "/candidate": {"rw": False, "type": "bind", "source": str(source)},
                    "/trusted": {"rw": False, "type": "bind", "source": str(trusted)},
                    "/out": {"rw": True, "type": "bind", "source": str(output)},
                },
            )
            try:
                subprocess.run(
                    [docker.binary, "start", "-a", identity],
                    capture_output=True, timeout=300, env=docker.environment,
                )  # fmt: skip
                exit_code = docker.json(["inspect", identity])[0]["State"]["ExitCode"]
            except subprocess.TimeoutExpired:
                exit_code = 124
        finally:
            if identity:
                docker.call(["rm", "-f", identity])
        verdict, detail = _junit_verdict(output / "report.xml")
        if exit_code != 0:
            verdict, detail = TESTS_FAILED, f"test run exited {exit_code}: {detail}"
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
        meaning="specified tests with the candidate imported; not safety, not approval",
    )
    return {
        "verdict": verdict,
        "detail": detail,
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


def status(state: State) -> dict:
    """What happened, kept separate from what is known about the outside world."""
    from .evidence import load_public_key, verify_offline

    public = load_public_key(str(state.path / "public-key.json"))
    journal = state.receipts_path.read_bytes() if state.receipts_path.exists() else b""
    report = verify_offline(journal, public)
    rows = [json.loads(line) for line in journal.splitlines()] if report["integrity"]["ok"] else []
    refused = [r for r in rows if r.get("decision") == "DENY"]
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
    }
