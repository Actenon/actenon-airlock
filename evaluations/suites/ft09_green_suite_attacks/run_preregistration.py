"""Pre-registration of verification policy, trusted tests, and baseline reproduction for Field Test 9."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from problem_setup import WORKSPACE_TESTS, INDEPENDENT_VERIFICATION_TESTS
from quality_gate import IndependentQualityGate, OperatorApprovalAuthority, REGRESSION_SUITE_HASH, WITHHELD_SUITE_HASH

def pre_register_policy():
    print("[Field Test 9] Pre-registering trusted verification policy...")
    work_dir = Path("/Users/ross/.gemini/antigravity/scratch/field_test_9").resolve()

    verifier_source_bytes = (work_dir / "quality_gate.py").read_bytes()
    verifier_sha256 = hashlib.sha256(verifier_source_bytes).hexdigest()

    regression_bytes = WORKSPACE_TESTS.encode("utf-8")
    regression_sha256 = hashlib.sha256(regression_bytes).hexdigest()

    withheld_bytes = INDEPENDENT_VERIFICATION_TESTS.encode("utf-8")
    withheld_sha256 = hashlib.sha256(withheld_bytes).hexdigest()

    correct_patch_bytes = (work_dir / "correct_patch.py").read_bytes()
    correct_patch_sha256 = hashlib.sha256(correct_patch_bytes).hexdigest()

    failed_patch_bytes = (work_dir / "failed_patch_ft7.py").read_bytes()
    failed_patch_sha256 = hashlib.sha256(failed_patch_bytes).hexdigest()

    # Reproduce passing and failing controls using target filename rate_limiter.py
    gate = IndependentQualityGate()
    
    ws_pass = work_dir / "ws_baseline_pass"
    ws_pass.mkdir(parents=True, exist_ok=True)
    candidate_pass = ws_pass / "rate_limiter.py"
    candidate_pass.write_bytes(correct_patch_bytes)

    ws_fail = work_dir / "ws_baseline_fail"
    ws_fail.mkdir(parents=True, exist_ok=True)
    candidate_fail = ws_fail / "rate_limiter.py"
    candidate_fail.write_bytes(failed_patch_bytes)

    rec_pass = gate.audit_and_verify(candidate_pass, ws_pass)
    rec_fail = gate.audit_and_verify(candidate_fail, ws_fail)

    assert rec_pass.verdict == "VERIFIED", f"Passing control failed: {rec_pass.rejection_reasons}"
    assert rec_fail.verdict == "FAILED", "Failing control unexpectedly passed"

    policy = {
        "evaluation_title": "ACTENON FIELD TEST 9 — THE GREEN TEST SUITE ATTACK",
        "verifier_source_sha256": verifier_sha256,
        "trusted_regression_suite_sha256": regression_sha256,
        "trusted_withheld_suite_sha256": withheld_sha256,
        "correct_patch_baseline_sha256": correct_patch_sha256,
        "failed_patch_baseline_sha256": failed_patch_sha256,
        "python_runtime": {
            "executable": sys.executable,
            "version": sys.version,
            "platform": sys.platform,
        },
        "compute_image_digest": "sha256:ad9ec2a8af538cc2eba16a86f5099f2c72671459aadf5448e92de2277ee57eb9",
        "signing_key_path": str(work_dir / "operator_ft9.key"),
        "baseline_reproduction": {
            "correct_control_verdict": rec_pass.verdict,
            "correct_control_reasons": rec_pass.rejection_reasons,
            "failed_control_verdict": rec_fail.verdict,
            "failed_control_reasons": rec_fail.rejection_reasons,
        },
    }

    out_file = work_dir / "preregistered_policy.json"
    out_file.write_text(json.dumps(policy, indent=2) + "\n")
    print(f"[Field Test 9] Pre-registered policy saved to {out_file}")
    print(json.dumps(policy, indent=2))
    return policy

if __name__ == "__main__":
    pre_register_policy()
