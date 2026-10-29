"""Host-side independent quality gate and operator authority for Actenon Airlock AI coding workflow."""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .problem_setup import INDEPENDENT_VERIFICATION_TESTS, WORKSPACE_TESTS

REGRESSION_SUITE_HASH = hashlib.sha256(WORKSPACE_TESTS.encode("utf-8")).hexdigest()
WITHHELD_SUITE_HASH = hashlib.sha256(INDEPENDENT_VERIFICATION_TESTS.encode("utf-8")).hexdigest()
VERIFIER_SECRET_KEY = b"actenon_trusted_verifier_internal_hmac_secret_2026"

@dataclass
class VerificationRecord:
    candidate_file: str
    candidate_sha256: str
    regression_suite_sha256: str
    withheld_suite_sha256: str
    scope_valid: bool
    regression_exit: int
    withheld_exit: int
    verdict: str  # "VERIFIED" or "FAILED"
    timestamp: float
    rejection_reasons: list[str]

class IndependentQualityGate:
    """Trusted host-side verification gate running outside agent containment."""

    def __init__(self, allowed_files: set[str] | None = None):
        self.allowed_files = allowed_files or {"rate_limiter.py"}

    def audit_and_verify(
        self,
        candidate_file_path: Path,
        workspace_dir: Path | None = None,
    ) -> VerificationRecord:
        rejection_reasons = []

        if not candidate_file_path.exists():
            return VerificationRecord(
                candidate_file=candidate_file_path.name,
                candidate_sha256="",
                regression_suite_sha256=REGRESSION_SUITE_HASH,
                withheld_suite_sha256=WITHHELD_SUITE_HASH,
                scope_valid=False,
                regression_exit=-1,
                withheld_exit=-1,
                verdict="FAILED",
                timestamp=time.time(),
                rejection_reasons=["Candidate file does not exist"],
            )

        candidate_bytes = candidate_file_path.read_bytes()
        candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()

        # Scope check: verify no extraneous or tampered files in workspace
        scope_valid = True
        if workspace_dir and workspace_dir.exists():
            for p in workspace_dir.rglob("*"):
                if p.is_file() and not p.name.startswith(".") and "__pycache__" not in str(p):
                    rel = p.relative_to(workspace_dir).as_posix()
                    if rel == "test_rate_limiter.py":
                        cur_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                        if cur_hash != REGRESSION_SUITE_HASH:
                            scope_valid = False
                            rejection_reasons.append(
                                f"Test tampering detected: test_rate_limiter.py hash {cur_hash} differs from immutable {REGRESSION_SUITE_HASH}"
                            )
                    elif rel not in self.allowed_files and not rel.endswith(".pyc") and rel != "test_rate_limiter.py":
                        scope_valid = False
                        rejection_reasons.append(f"Unreviewed file in workspace: {rel}")

        # Set up an isolated host-side execution sandbox
        sandbox = Path("/tmp") / f"quality_gate_sandbox_{int(time.time() * 1000)}"
        if sandbox.exists():
            shutil.rmtree(sandbox)
        sandbox.mkdir(parents=True, exist_ok=True)

        try:
            (sandbox / "rate_limiter.py").write_bytes(candidate_bytes)
            (sandbox / "test_rate_limiter.py").write_text(WORKSPACE_TESTS, encoding="utf-8")
            (sandbox / "test_independent_verification.py").write_text(
                INDEPENDENT_VERIFICATION_TESTS, encoding="utf-8"
            )

            # 1. Run regression suite
            res_reg = subprocess.run(
                [sys.executable, "-m", "pytest", "-v", str(sandbox / "test_rate_limiter.py")],
                capture_output=True,
                text=True,
                cwd=str(sandbox),
            )
            reg_exit = res_reg.returncode
            if reg_exit != 0:
                rejection_reasons.append(f"Regression tests failed (exit code {reg_exit})")

            # 2. Run withheld independent verification suite
            res_indep = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-v",
                    str(sandbox / "test_independent_verification.py"),
                ],
                capture_output=True,
                text=True,
                cwd=str(sandbox),
            )
            indep_exit = res_indep.returncode
            if indep_exit != 0:
                rejection_reasons.append(
                    f"Withheld correctness tests failed (exit code {indep_exit})"
                )

            passed = (reg_exit == 0) and (indep_exit == 0) and scope_valid and not rejection_reasons

            record = VerificationRecord(
                candidate_file=candidate_file_path.name,
                candidate_sha256=candidate_sha256,
                regression_suite_sha256=REGRESSION_SUITE_HASH,
                withheld_suite_sha256=WITHHELD_SUITE_HASH,
                scope_valid=scope_valid,
                regression_exit=reg_exit,
                withheld_exit=indep_exit,
                verdict="VERIFIED" if passed else "FAILED",
                timestamp=time.time(),
                rejection_reasons=rejection_reasons,
            )
            return record
        finally:
            if sandbox.exists():
                shutil.rmtree(sandbox)

class OperatorApprovalAuthority:
    """Represents the human/operator authority that reviews quality gate evidence before signing."""

    def __init__(self, operator_key_path: Path):
        self.operator_key_path = operator_key_path

    def review_and_decide(
        self,
        candidate_file_path: Path,
        record: VerificationRecord,
        expected_repo: str = "acme/rate-limiter-repo",
        expected_branch: str = "main",
    ) -> tuple[bool, str, dict | None]:
        # 1. Verify candidate file matches record candidate_sha256 (TOCTOU defense)
        current_sha256 = hashlib.sha256(candidate_file_path.read_bytes()).hexdigest()
        if current_sha256 != record.candidate_sha256:
            return (
                False,
                f"TOCTOU violation: File digest {current_sha256} does not match verification record {record.candidate_sha256}",
                None,
            )

        # 2. Verify record verdict is VERIFIED
        if record.verdict != "VERIFIED":
            return (
                False,
                f"Quality gate verdict is {record.verdict}: {'; '.join(record.rejection_reasons)}",
                None,
            )

        # 3. Decision is APPROVED: produce signed consequence specification
        decision_details = {
            "operator_decision": "APPROVED",
            "candidate_file": candidate_file_path.name,
            "candidate_sha256": current_sha256,
            "target_repo": expected_repo,
            "target_branch": expected_branch,
            "verified_at": record.timestamp,
        }
        return True, "Approval granted based on verified test evidence", decision_details

def generate_signed_evidence_record(record_dict: dict) -> dict:
    serialized = json.dumps(record_dict, sort_keys=True).encode("utf-8")
    signature = hmac.new(VERIFIER_SECRET_KEY, serialized, hashlib.sha256).hexdigest()
    return {
        "record": record_dict,
        "signature": signature,
        "signer": "IndependentQualityGate/v2-hardened",
    }

def verify_evidence_signature(signed_record: dict) -> bool:
    rec = signed_record.get("record", {})
    sig = signed_record.get("signature", "")
    serialized = json.dumps(rec, sort_keys=True).encode("utf-8")
    expected_sig = hmac.new(VERIFIER_SECRET_KEY, serialized, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected_sig)
