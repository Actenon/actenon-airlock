"""EXPERIMENTAL evaluation-only evidence and operator-approval helpers.

Not a production component and not part of the ``actenon_airlock`` package.
See evaluations/CORRECTIONS.md for why the original versions were withdrawn:

* Evidence signatures used an HMAC key written in this file, so anyone could
  forge a "verified" record. Records are now signed only with an Ed25519 key
  the caller supplies at run time, under a domain that cannot be confused with
  an approval.
* ``OperatorApprovalAuthority`` turned a passing test verdict into APPROVED
  without any operator. It now issues an approval *request*; APPROVED requires
  an Ed25519 operator signature over that exact request.
* ``IndependentQualityGate`` ran candidate code with pytest on the host. It now
  refuses; use ``ContainerQualityGate`` from ``hardened_verifier``.

A passing test run is an observation that specified tests passed with the
candidate imported. It is not evidence that the candidate is correct or safe,
and it never approves anything by itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .problem_setup import INDEPENDENT_VERIFICATION_TESTS, WORKSPACE_TESTS

EXPERIMENTAL = True
REGRESSION_SUITE_HASH = hashlib.sha256(WORKSPACE_TESTS.encode("utf-8")).hexdigest()
WITHHELD_SUITE_HASH = hashlib.sha256(INDEPENDENT_VERIFICATION_TESTS.encode("utf-8")).hexdigest()

# Domain separation: an evidence signature can never verify as an approval.
EVIDENCE_DOMAIN = b"actenon-airlock/evaluation-evidence/v1\n"
APPROVAL_DOMAIN = b"actenon-airlock/evaluation-approval-request/v1\n"
TESTS_PASSED = "TESTS_PASSED"
TESTS_FAILED = "TESTS_FAILED"


class HostExecutionRefused(RuntimeError):
    """Candidate code may not be executed on the host."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return _b64(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


@dataclass
class VerificationRecord:
    candidate_file: str
    candidate_sha256: str
    regression_suite_sha256: str
    withheld_suite_sha256: str
    scope_valid: bool
    regression_exit: int
    withheld_exit: int
    verdict: str  # TESTS_PASSED or TESTS_FAILED; never an approval
    timestamp: float
    rejection_reasons: list[str]


class IndependentQualityGate:
    """Withdrawn: it executed untrusted candidates with pytest on the host."""

    def __init__(self, allowed_files: set[str] | None = None):
        self.allowed_files = allowed_files or {"rate_limiter.py"}

    def audit_and_verify(self, candidate_file_path: Path, workspace_dir: Path | None = None):
        raise HostExecutionRefused(
            "IndependentQualityGate executed candidate code on the host and is withdrawn; "
            "use evaluations.harness.hardened_verifier.ContainerQualityGate"
        )


def generate_signed_evidence_record(record: dict, signing_key: Ed25519PrivateKey) -> dict:
    """Sign a record with a key the caller holds outside any candidate environment."""
    signature = signing_key.sign(EVIDENCE_DOMAIN + canonical(record))
    return {
        "record": record,
        "signature": _b64(signature),
        "public_key": public_key_b64(signing_key),
        "signer": "experimental-evaluation-evidence/v1",
    }


def verify_evidence_signature(signed_record: dict, trusted_public_key: str) -> bool:
    """Verify against a public key the verifier already trusts, never the embedded one."""
    try:
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(trusted_public_key, validate=True)
        )
        key.verify(
            base64.b64decode(signed_record["signature"], validate=True),
            EVIDENCE_DOMAIN + canonical(signed_record["record"]),
        )
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


@dataclass(frozen=True)
class ApprovalRequest:
    """What an operator is asked to sign. Producing it approves nothing."""

    candidate_file: str
    candidate_sha256: str
    evidence_sha256: str
    test_verdict: str
    target_repo: str
    target_branch: str
    operator_key_id: str

    def payload(self) -> bytes:
        return APPROVAL_DOMAIN + canonical(asdict(self))


def sign_approval_request(request: ApprovalRequest, operator_key: Ed25519PrivateKey) -> str:
    """Run by the operator, in a trusted context, after reviewing the request."""
    return _b64(operator_key.sign(request.payload()))


class OperatorApprovalAuthority:
    """Issues approval requests and accepts only genuine operator signatures over them."""

    def __init__(self, operator_public_key: str):
        self.operator_public_key = operator_public_key
        self._key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(operator_public_key, validate=True)
        )

    def request_approval(
        self,
        candidate_file_path: Path,
        record: VerificationRecord,
        evidence: dict,
        expected_repo: str = "acme/rate-limiter-repo",
        expected_branch: str = "main",
    ) -> tuple[ApprovalRequest | None, str]:
        current = hashlib.sha256(candidate_file_path.read_bytes()).hexdigest()
        if current != record.candidate_sha256:
            return None, (
                f"TOCTOU violation: file digest {current} does not match "
                f"verification record {record.candidate_sha256}"
            )
        if record.verdict != TESTS_PASSED:
            return None, f"Test verdict is {record.verdict}: {'; '.join(record.rejection_reasons)}"
        if evidence.get("record", {}).get("candidate_sha256") != current:
            return None, "Evidence does not describe this candidate"
        request = ApprovalRequest(
            candidate_file=candidate_file_path.name,
            candidate_sha256=current,
            evidence_sha256=hashlib.sha256(canonical(evidence)).hexdigest(),
            test_verdict=record.verdict,
            target_repo=expected_repo,
            target_branch=expected_branch,
            operator_key_id=hashlib.sha256(self.operator_public_key.encode()).hexdigest()[:16],
        )
        return request, "Awaiting an operator signature; tests passing is not approval"

    def accept_signed_approval(
        self, request: ApprovalRequest, signature: str, candidate_file_path: Path
    ) -> tuple[bool, str]:
        try:
            self._key.verify(base64.b64decode(signature, validate=True), request.payload())
        except (InvalidSignature, ValueError):
            return False, "Operator signature does not verify for this exact request"
        current = hashlib.sha256(candidate_file_path.read_bytes()).hexdigest()
        if current != request.candidate_sha256:
            return False, "Candidate changed after the operator signed"
        return True, "APPROVED by a verified operator signature"
