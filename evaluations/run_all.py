#!/usr/bin/env python3
"""Smoke checks for the EXPERIMENTAL evaluation harness.

Never executes candidate code on the host. The container test runner runs only
when ``--image`` names a local image with python3 and pytest; otherwise that
step is reported as NOT RUN rather than passed.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from evaluations.harness.hardened_verifier import ContainerQualityGate  # noqa: E402
from evaluations.harness.mock_github_fixture import (  # noqa: E402
    GitHubContentsProviderFixture,
    ProviderFixtureState,
)
from evaluations.harness.problem_setup import BUGGY_RATE_LIMITER, CORRECT_RATE_LIMITER  # noqa: E402
from evaluations.harness.quality_gate import (  # noqa: E402
    TESTS_FAILED,
    TESTS_PASSED,
    HostExecutionRefused,
    IndependentQualityGate,
    OperatorApprovalAuthority,
    VerificationRecord,
    generate_signed_evidence_record,
    public_key_b64,
    sign_approval_request,
    verify_evidence_signature,
)


def run_smoke_evaluations(image: str | None) -> int:
    failures: list[str] = []

    def check(label: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        if not ok:
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        marker = tmp_path / "executed"
        candidate = tmp_path / "rate_limiter.py"
        candidate.write_text(f"open({str(marker)!r}, 'w').close()\n" + CORRECT_RATE_LIMITER)

        print("[1] Host execution is refused")
        try:
            IndependentQualityGate().audit_and_verify(candidate)
            check("host gate refused", False)
        except HostExecutionRefused:
            check("host gate refused", True)
        check("candidate was not executed", not marker.exists())

        print("[2] Evidence is signed with a caller-held key")
        verifier_key = Ed25519PrivateKey.generate()
        record = {"candidate_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
                  "verdict": TESTS_PASSED}  # fmt: skip
        evidence = generate_signed_evidence_record(record, verifier_key)
        trusted = public_key_b64(verifier_key)
        check("genuine evidence verifies", verify_evidence_signature(evidence, trusted))
        forged = generate_signed_evidence_record(record, Ed25519PrivateKey.generate())
        check("evidence from another key is rejected", not verify_evidence_signature(forged, trusted))

        print("[3] Approval needs an operator signature")
        operator = Ed25519PrivateKey.generate()
        authority = OperatorApprovalAuthority(public_key_b64(operator))
        rec = VerificationRecord("rate_limiter.py", record["candidate_sha256"], "", "", True, 0, 0,
                                 TESTS_PASSED, 0.0, [])  # fmt: skip
        request, _ = authority.request_approval(candidate, rec, evidence)
        check("passing tests produce a request, not an approval", request is not None)
        ok, _ = authority.accept_signed_approval(
            request, sign_approval_request(request, Ed25519PrivateKey.generate()), candidate
        )
        check("a non-operator signature is rejected", not ok)
        ok, _ = authority.accept_signed_approval(
            request, sign_approval_request(request, operator), candidate
        )
        check("the operator's signature approves", ok)

    print("[4] Container test runner")
    if image is None:
        print("  NOT RUN (pass --image to run candidates in an isolated container)")
    else:
        gate = ContainerQualityGate(image)
        with tempfile.TemporaryDirectory() as tmp:
            for name, code, expected in (("correct", CORRECT_RATE_LIMITER, TESTS_PASSED),
                                         ("buggy", BUGGY_RATE_LIMITER, TESTS_FAILED)):  # fmt: skip
                path = Path(tmp) / name / "rate_limiter.py"
                path.parent.mkdir()
                path.write_text(code)
                check(f"{name} candidate -> {expected}", gate.audit_and_verify(path).verdict == expected)

    print("[5] GitHub Contents provider fixture")
    fixture = GitHubContentsProviderFixture(ProviderFixtureState())
    resp = fixture(httpx.Request("GET", "https://api.github.com/repos/acme/disposable-target"))
    check("preflight answers", resp.status_code == 200)

    print(f"\n{len(failures)} failure(s)" + ("" if image else "; container runner NOT RUN"))
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", help="local image with python3 and pytest")
    sys.exit(run_smoke_evaluations(parser.parse_args().image))
