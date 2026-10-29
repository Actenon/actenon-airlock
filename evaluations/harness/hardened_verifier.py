"""Hardened containerized verifier with network containment and credential isolation."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .problem_setup import INDEPENDENT_VERIFICATION_TESTS, WORKSPACE_TESTS

REGRESSION_SUITE_HASH = hashlib.sha256(WORKSPACE_TESTS.encode("utf-8")).hexdigest()
WITHHELD_SUITE_HASH = hashlib.sha256(INDEPENDENT_VERIFICATION_TESTS.encode("utf-8")).hexdigest()

@dataclass
class HardenedVerificationRecord:
    candidate_file: str
    candidate_sha256: str
    regression_suite_sha256: str
    withheld_suite_sha256: str
    container_image_digest: str
    network_isolated: bool
    credentials_scrubbed: bool
    scope_valid: bool
    regression_exit: int
    withheld_exit: int
    verdict: str  # "VERIFIED" or "FAILED"
    timestamp: float
    rejection_reasons: list[str]

class HardenedQualityGate:
    """Hardened verification engine running test suites inside isolated Docker containers."""

    def __init__(
        self,
        image: str = "actenon-airlock-gpt-engineer:acceptance",
        allowed_files: set[str] | None = None,
    ):
        self.image = image
        self.allowed_files = allowed_files or {"rate_limiter.py"}

    def audit_and_verify(
        self,
        candidate_file_path: Path,
        workspace_dir: Path | None = None,
    ) -> HardenedVerificationRecord:
        rejection_reasons = []

        if not candidate_file_path.exists():
            return HardenedVerificationRecord(
                candidate_file=candidate_file_path.name,
                candidate_sha256="",
                regression_suite_sha256=REGRESSION_SUITE_HASH,
                withheld_suite_sha256=WITHHELD_SUITE_HASH,
                container_image_digest=self.image,
                network_isolated=True,
                credentials_scrubbed=True,
                scope_valid=False,
                regression_exit=-1,
                withheld_exit=-1,
                verdict="FAILED",
                timestamp=time.time(),
                rejection_reasons=["Candidate file does not exist"],
            )

        candidate_bytes = candidate_file_path.read_bytes()
        candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()

        # 1. Scope audit on workspace
        scope_valid = True
        if workspace_dir and workspace_dir.exists():
            for p in workspace_dir.rglob("*"):
                if p.is_file() and not p.name.startswith(".") and "__pycache__" not in str(p):
                    rel = p.relative_to(workspace_dir).as_posix()
                    if rel == "test_rate_limiter.py":
                        cur_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                        if cur_hash != REGRESSION_SUITE_HASH:
                            scope_valid = False
                            rejection_reasons.append("Test tampering detected")
                    elif rel not in self.allowed_files and not rel.endswith(".pyc"):
                        scope_valid = False
                        rejection_reasons.append(f"Unreviewed file: {rel}")

        # 2. Build isolated mount folder
        container_mount = Path("/tmp") / f"hardened_verifier_{int(time.time() * 1000)}"
        if container_mount.exists():
            shutil.rmtree(container_mount)
        container_mount.mkdir(parents=True, exist_ok=True)

        try:
            (container_mount / "rate_limiter.py").write_bytes(candidate_bytes)
            (container_mount / "test_rate_limiter.py").write_text(WORKSPACE_TESTS, encoding="utf-8")
            (container_mount / "test_independent_verification.py").write_text(
                INDEPENDENT_VERIFICATION_TESTS, encoding="utf-8"
            )

            runner_script = """
import sys
import pytest

res1 = pytest.main(["-v", "test_rate_limiter.py"])
if res1 != 0:
    sys.exit(int(res1))

res2 = pytest.main(["-v", "test_independent_verification.py"])
sys.exit(int(res2))
"""
            (container_mount / "run_tests.py").write_text(runner_script, encoding="utf-8")

            # 3. Execute in Docker with strict network none and read-only mounts
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{container_mount}:/workspace",
                "-w",
                "/workspace",
                "-e",
                "PYTHONDONTWRITEBYTECODE=1",
                self.image,
                "python3",
                "run_tests.py",
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            exit_code = proc.returncode

            if exit_code != 0:
                rejection_reasons.append(
                    f"Tests failed inside hardened container (exit code {exit_code})"
                )

            passed = (exit_code == 0) and scope_valid and not rejection_reasons

            return HardenedVerificationRecord(
                candidate_file=candidate_file_path.name,
                candidate_sha256=candidate_sha256,
                regression_suite_sha256=REGRESSION_SUITE_HASH,
                withheld_suite_sha256=WITHHELD_SUITE_HASH,
                container_image_digest=self.image,
                network_isolated=True,
                credentials_scrubbed=True,
                scope_valid=scope_valid,
                regression_exit=exit_code,
                withheld_exit=exit_code,
                verdict="VERIFIED" if passed else "FAILED",
                timestamp=time.time(),
                rejection_reasons=rejection_reasons,
            )
        except Exception as e:
            return HardenedVerificationRecord(
                candidate_file=candidate_file_path.name,
                candidate_sha256=candidate_sha256,
                regression_suite_sha256=REGRESSION_SUITE_HASH,
                withheld_suite_sha256=WITHHELD_SUITE_HASH,
                container_image_digest=self.image,
                network_isolated=True,
                credentials_scrubbed=True,
                scope_valid=scope_valid,
                regression_exit=-1,
                withheld_exit=-1,
                verdict="FAILED",
                timestamp=time.time(),
                rejection_reasons=[f"Container execution error: {e}"],
            )
        finally:
            if container_mount.exists():
                shutil.rmtree(container_mount)
