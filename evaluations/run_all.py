#!/usr/bin/env python3
"""Actenon Airlock Field Evaluations Master Runner.

Runs and audits the independent evaluation suites and quality gate controls.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Add repo root to pythonpath
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from evaluations.harness.candidates import (
    CANDIDATE_A_DORMANT_BACKDOOR,
    CANDIDATE_B_TEST_EVASION,
    CANDIDATE_C_IMPORT_TIME_SIDE_EFFECT,
)
from evaluations.harness.mock_github_fixture import (
    GitHubContentsProviderFixture,
    ProviderFixtureState,
)
from evaluations.harness.problem_setup import (
    BUGGY_RATE_LIMITER,
    CORRECT_RATE_LIMITER,
)
from evaluations.harness.quality_gate import (
    IndependentQualityGate,
    OperatorApprovalAuthority,
    generate_signed_evidence_record,
    verify_evidence_signature,
)

def run_smoke_evaluations() -> int:
    print("=" * 70)
    print("ACTENON AIRLOCK: INDEPENDENT FIELD EVALUATION SUITE AUDIT")
    print("=" * 70)

    overall_failures = 0

    # 1. Audit Problem Setup & Baseline Defect
    print("\n[Step 1] Verifying TokenBucket Problem Setup...")
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        buggy_file = tmp_path / "rate_limiter.py"
        buggy_file.write_text(BUGGY_RATE_LIMITER, encoding="utf-8")
        gate = IndependentQualityGate()
        rec_buggy = gate.audit_and_verify(buggy_file)
        if rec_buggy.verdict == "FAILED":
            print("  ✓ Buggy baseline correctly rejected by quality gate (verdict=FAILED)")
        else:
            print(f"  ✗ Buggy baseline unexpectedly verified: {rec_buggy.verdict}")
            overall_failures += 1

    # 2. Audit Correct Reference Patch
    print("\n[Step 2] Verifying Reference Implementation Patch...")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        correct_file = tmp_path / "rate_limiter.py"
        correct_file.write_text(CORRECT_RATE_LIMITER, encoding="utf-8")
        rec_correct = gate.audit_and_verify(correct_file)
        if rec_correct.verdict == "VERIFIED":
            print("  ✓ Reference patch verified by quality gate (verdict=VERIFIED)")
        else:
            print(f"  ✗ Reference patch failed: {rec_correct.rejection_reasons}")
            overall_failures += 1

    # 3. Audit Operator Approval Authority Defenses
    print("\n[Step 3] Verifying Operator Approval Authority Protections (Attacks A-G)...")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        key_file = tmp_path / "operator.key"
        key_file.write_text("synthetic-key", encoding="utf-8")
        authority = OperatorApprovalAuthority(key_file)

        # TOCTOU defense
        correct_file = tmp_path / "rate_limiter.py"
        correct_file.write_text(CORRECT_RATE_LIMITER, encoding="utf-8")
        tampered_file = tmp_path / "tampered.py"
        tampered_file.write_text(CANDIDATE_A_DORMANT_BACKDOOR, encoding="utf-8")

        allowed, msg, _ = authority.review_and_decide(tampered_file, rec_correct)
        if not allowed and "TOCTOU" in msg:
            print("  ✓ TOCTOU patch substitution attack blocked")
        else:
            print("  ✗ TOCTOU substitution attack failed to block")
            overall_failures += 1

    # 4. Audit Cryptographic Evidence Binding
    print("\n[Step 4] Verifying HMAC Cryptographic Evidence Binding...")
    raw_record = {
        "candidate_file": "rate_limiter.py",
        "candidate_sha256": "abc12345",
        "verdict": "VERIFIED",
        "timestamp": time.time(),
    }
    signed_rec = generate_signed_evidence_record(raw_record)
    if verify_evidence_signature(signed_rec):
        print("  ✓ Valid HMAC signature correctly verified")
    else:
        print("  ✗ Valid HMAC signature verification failed")
        overall_failures += 1

    # Tamper with record
    signed_rec["record"]["verdict"] = "TAMPERED_VERDICT"
    if not verify_evidence_signature(signed_rec):
        print("  ✓ Tampered evidence record signature verification failed as expected")
    else:
        print("  ✗ Tampered record signature unexpectedly passed")
        overall_failures += 1

    # 5. Audit GitHub Contents Provider Fixture
    print("\n[Step 5] Verifying GitHub Contents API Consequence Fixture...")
    fixture_state = ProviderFixtureState()
    fixture = GitHubContentsProviderFixture(fixture_state)
    import httpx
    req = httpx.Request("GET", "https://api.github.com/repos/acme/disposable-target")
    resp = fixture(req)
    if resp.status_code == 200 and resp.json().get("full_name") == "acme/disposable-target":
        print("  ✓ GitHub provider fixture preflight response verified")
    else:
        print(f"  ✗ GitHub provider fixture error: {resp.status_code}")
        overall_failures += 1

    print("\n" + "=" * 70)
    if overall_failures == 0:
        print("ALL EVALUATION SUITE AUDIT CHECKS PASSED.")
        print("=" * 70)
        return 0
    else:
        print(f"EVALUATION CHECKS FAILED: {overall_failures} errors.")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Actenon Airlock Field Evaluations Runner")
    args = parser.parse_args()
    sys.exit(run_smoke_evaluations())
