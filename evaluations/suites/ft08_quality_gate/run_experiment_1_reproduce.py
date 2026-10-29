"""Experiment 1: Reproduce the failed-patch scenario and analyze Airlock authorization boundary."""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from problem_setup import WORKSPACE_TESTS, INDEPENDENT_VERIFICATION_TESTS

def run_pytest(test_path: Path) -> tuple[int, str]:
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", str(test_path)],
        capture_output=True,
        text=True,
    )
    return res.returncode, res.stdout + res.stderr

def run_experiment_1():
    print("[Experiment 1] Reproducing failed-patch test outcomes...")
    work_dir = Path("/Users/ross/.gemini/antigravity/scratch/field_test_8/exp1_reproduce")
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)

    failed_patch = Path("/Users/ross/.gemini/antigravity/scratch/field_test_8/failed_patch_ft7.py").read_bytes()
    patch_sha256 = hashlib.sha256(failed_patch).hexdigest()
    print(f"  Failed patch digest: {patch_sha256}")

    # Set up files in temporary workspace
    (work_dir / "rate_limiter.py").write_bytes(failed_patch)
    (work_dir / "test_rate_limiter.py").write_text(WORKSPACE_TESTS)
    (work_dir / "test_independent_verification.py").write_text(INDEPENDENT_VERIFICATION_TESTS)

    # Run regression tests
    reg_code, reg_out = run_pytest(work_dir / "test_rate_limiter.py")
    print(f"  Regression tests exit code: {reg_code} (Expected: 1)")

    # Run independent verification tests
    indep_code, indep_out = run_pytest(work_dir / "test_independent_verification.py")
    print(f"  Independent verification exit code: {indep_code} (Expected: 1)")

    # Architectural analysis of publication authorization
    analysis = {
        "patch_digest": patch_sha256,
        "regression_exit": reg_code,
        "regression_passed": reg_code == 0,
        "independent_exit": indep_code,
        "independent_passed": indep_code == 0,
        "trusted_component_authorizing_publication": "Operator Signing Key (via airlock init --approve --reconciler-key)",
        "airlock_built_in_correctness_check": None,
        "airlock_design_boundary": (
            "Airlock enforces cryptographic authority, transport isolation, and consequence matching. "
            "It checks that an outbound action matches a signed ReviewedGitHubCreate profile. "
            "Airlock has NO built-in semantics, test runners, or code-correctness prerequisites. "
            "Exact-authority enforcement guarantees consequence fidelity, NOT source code quality."
        ),
        "why_failed_patch_shipped_in_ft7": (
            "In Field Test 7, the test harness simulated human review by signing the consequence profile "
            "directly for the generated artifact without requiring a passing test gate. Airlock's "
            "ProtectedBroker correctly verified the signature and dispatched the PUT request as instructed."
        ),
    }

    out_file = Path("/Users/ross/.gemini/antigravity/scratch/field_test_8/experiment1_summary.json")
    out_file.write_text(json.dumps(analysis, indent=2) + "\n")
    print(f"[Experiment 1] Summary written to {out_file}")
    print(json.dumps(analysis, indent=2))
    return analysis

if __name__ == "__main__":
    run_experiment_1()
