"""EXPERIMENTAL container test runner for evaluation candidates.

Not a production component and not part of the ``actenon_airlock`` package.
It replaces the withdrawn ``HardenedQualityGate``, which mounted the trusted
tests read-write (a candidate could rewrite the withheld suite), trusted a bare
container exit code (``os._exit(0)`` at import passed), ran both suites in the
candidate's process, applied no capability, user or resource limits, and
recorded isolation as constants. See evaluations/CORRECTIONS.md.

What this runner does:

* Copies only the candidate file into a fresh directory. Candidate and trusted
  tests are mounted read-only; only ``/out`` (reports) and a noexec ``/tmp``
  are writable.
* Runs each suite in its own container: no network, read-only root, all
  capabilities dropped, no-new-privileges, uid 65534, PID/memory/CPU limits,
  image addressed by its local ID.
* Creates the container, inspects it and refuses to start it unless the
  observed settings match, and records what it observed.
* Requires exit status 0 AND a JUnit report in which every test defined by the
  trusted suite passed, so a candidate that exits early fails.

What it cannot do: the candidate runs in the same interpreter as the tests, so
it can still alter test behaviour or forge the report it writes. The result is
``TESTS_PASSED`` (specified tests passed with the candidate imported), never a
correctness or safety verdict, and never an approval.
"""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .problem_setup import INDEPENDENT_VERIFICATION_TESTS, WORKSPACE_TESTS
from .quality_gate import (
    REGRESSION_SUITE_HASH,
    TESTS_FAILED,
    TESTS_PASSED,
    WITHHELD_SUITE_HASH,
    VerificationRecord,
)

EXPERIMENTAL = True
UID = "65534:65534"
SUITES = {
    "regression": ("test_rate_limiter.py", WORKSPACE_TESTS),
    "withheld": ("test_independent_verification.py", INDEPENDENT_VERIFICATION_TESTS),
}


class IsolationError(RuntimeError):
    """The container's observed settings do not match the required isolation."""


@dataclass
class ContainerVerificationRecord(VerificationRecord):
    image_id: str
    observed_isolation: dict = field(default_factory=dict)
    junit_sha256: dict = field(default_factory=dict)


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _test_names(source: str) -> set[str]:
    return {
        node.name
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }


def _junit_outcomes(path: Path) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            outcomes[case.get("name", "")] = "failed"
        elif case.find("skipped") is not None:
            outcomes[case.get("name", "")] = "skipped"
        else:
            outcomes[case.get("name", "")] = "passed"
    return outcomes


class ContainerQualityGate:
    def __init__(
        self,
        image: str,
        *,
        allowed_files: set[str] | None = None,
        timeout_seconds: float = 120,
        memory_bytes: int = 512 * 1024 * 1024,
        nano_cpus: int = 1_000_000_000,
        pids: int = 128,
    ):
        self.image = image
        self.allowed_files = allowed_files or {"rate_limiter.py"}
        self.timeout_seconds = timeout_seconds
        self.memory_bytes = memory_bytes
        self.nano_cpus = nano_cpus
        self.pids = pids

    def image_id(self) -> str:
        proc = _docker("image", "inspect", self.image, "--format", "{{.Id}}")
        image_id = proc.stdout.strip()
        if proc.returncode != 0 or not image_id.startswith("sha256:"):
            raise IsolationError(f"image {self.image!r} is not available locally")
        return image_id

    def _check(self, info: dict, image_id: str, mounts: dict[str, bool]) -> dict:
        host = info["HostConfig"]
        observed = {
            "image": info.get("Image"),
            "network_mode": host.get("NetworkMode"),
            "readonly_rootfs": host.get("ReadonlyRootfs"),
            "privileged": host.get("Privileged"),
            "cap_drop": host.get("CapDrop"),
            "cap_add": host.get("CapAdd"),
            "security_opt": host.get("SecurityOpt"),
            "pids_limit": host.get("PidsLimit"),
            "memory": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "user": info["Config"].get("User"),
            "mounts": {m["Destination"]: m["RW"] for m in info.get("Mounts", [])},
            "tmpfs": sorted((host.get("Tmpfs") or {}).keys()),
        }
        problems = [
            name
            for name, ok in (
                ("image", observed["image"] == image_id),
                ("network", observed["network_mode"] == "none"),
                ("readonly_rootfs", observed["readonly_rootfs"] is True),
                ("privileged", observed["privileged"] is False),
                ("cap_drop", observed["cap_drop"] == ["ALL"] and not observed["cap_add"]),
                (
                    "no_new_privileges",
                    any(o.startswith("no-new-privileges") for o in observed["security_opt"] or []),
                ),
                ("pids", observed["pids_limit"] == self.pids),
                ("memory", observed["memory"] == self.memory_bytes),
                ("cpus", observed["nano_cpus"] == self.nano_cpus),
                ("user", observed["user"] == UID),
                ("mounts", observed["mounts"] == mounts),
                ("tmpfs", observed["tmpfs"] == ["/tmp"]),
            )
            if not ok
        ]
        if problems:
            raise IsolationError(f"container settings not as required: {problems}")
        return observed

    def _run_suite(self, image_id: str, candidate: Path, trusted: Path, out: Path, suite: str):
        test_file, _ = SUITES[suite]
        name = f"airlock-eval-{uuid.uuid4().hex[:12]}"
        create = _docker(
            "create", "--name", name,
            "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids),
            "--memory", str(self.memory_bytes), "--memory-swap", str(self.memory_bytes),
            "--cpus", str(self.nano_cpus / 1e9), "--user", UID,
            "--mount", f"type=bind,src={candidate},dst=/candidate,readonly",
            "--mount", f"type=bind,src={trusted},dst=/trusted,readonly",
            "--mount", f"type=bind,src={out},dst=/out",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/candidate", "-e", "HOME=/tmp",
            "-w", "/tmp", image_id,
            "python3", "-m", "pytest", "-p", "no:cacheprovider", "-c", "/dev/null",
            "--rootdir", "/trusted", "--confcutdir", "/trusted", "-q",
            f"--junitxml=/out/{suite}.xml", f"/trusted/{test_file}",
        )  # fmt: skip
        if create.returncode != 0:
            raise IsolationError(f"docker create failed: {create.stderr.strip()[:300]}")
        try:
            info = json.loads(_docker("inspect", name).stdout)[0]
            observed = self._check(
                info, image_id, {"/candidate": False, "/trusted": False, "/out": True}
            )
            try:
                _docker("start", "-a", name, timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                _docker("kill", name)
                return -1, observed, None, "timed out"
            state = json.loads(_docker("inspect", name).stdout)[0]["State"]
            return state.get("ExitCode", -1), observed, out / f"{suite}.xml", None
        finally:
            _docker("rm", "-f", name)

    def audit_and_verify(
        self, candidate_file_path: Path, workspace_dir: Path | None = None
    ) -> ContainerVerificationRecord:
        reasons: list[str] = []
        candidate_bytes = candidate_file_path.read_bytes()
        candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()

        scope_valid = True
        if workspace_dir is not None and workspace_dir.exists():
            for p in workspace_dir.rglob("*"):
                if not p.is_file() or "__pycache__" in p.parts:
                    continue
                rel = p.relative_to(workspace_dir).as_posix()
                if rel == "test_rate_limiter.py":
                    if hashlib.sha256(p.read_bytes()).hexdigest() != REGRESSION_SUITE_HASH:
                        scope_valid = False
                        reasons.append("Test tampering detected: test_rate_limiter.py changed")
                elif rel not in self.allowed_files:
                    scope_valid = False
                    reasons.append(f"Unreviewed file in workspace: {rel}")

        image_id = self.image_id()
        observed: dict = {}
        junit: dict = {}
        exits: dict[str, int] = {}
        with tempfile.TemporaryDirectory(prefix="airlock-eval-") as tmp:
            root = Path(tmp)
            candidate, trusted = root / "candidate", root / "trusted"
            for d in (candidate, trusted):
                d.mkdir()
                d.chmod(0o755)
            (candidate / "rate_limiter.py").write_bytes(candidate_bytes)
            for test_file, source in SUITES.values():
                (trusted / test_file).write_text(source, encoding="utf-8")
            for f in [*candidate.iterdir(), *trusted.iterdir()]:
                f.chmod(0o444)
            for suite, (_, source) in SUITES.items():
                out = root / f"out-{suite}"
                out.mkdir()
                out.chmod(0o777)
                code, observed[suite], report, error = self._run_suite(
                    image_id, candidate, trusted, out, suite
                )
                exits[suite] = code
                if error or code != 0:
                    reasons.append(
                        f"{suite} suite exited {code}{' (' + error + ')' if error else ''}"
                    )
                    continue
                if report is None or not report.is_file():
                    reasons.append(f"{suite} suite produced no JUnit report")
                    continue
                junit[suite] = hashlib.sha256(report.read_bytes()).hexdigest()
                outcomes = _junit_outcomes(report)
                expected = _test_names(source)
                if set(outcomes) != expected or any(o != "passed" for o in outcomes.values()):
                    reasons.append(f"{suite} suite did not pass every defined test: {outcomes}")
            shutil.rmtree(root, ignore_errors=True)

        passed = scope_valid and not reasons
        return ContainerVerificationRecord(
            candidate_file=candidate_file_path.name,
            candidate_sha256=candidate_sha256,
            regression_suite_sha256=REGRESSION_SUITE_HASH,
            withheld_suite_sha256=WITHHELD_SUITE_HASH,
            scope_valid=scope_valid,
            regression_exit=exits.get("regression", -1),
            withheld_exit=exits.get("withheld", -1),
            verdict=TESTS_PASSED if passed else TESTS_FAILED,
            timestamp=time.time(),
            rejection_reasons=reasons,
            image_id=image_id,
            observed_isolation=observed,
            junit_sha256=junit,
        )
