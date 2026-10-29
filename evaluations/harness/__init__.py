"""Evaluations harness package exposing fixtures, problem setups, and verification gates."""

from .candidates import (
    CANDIDATE_A_DORMANT_BACKDOOR,
    CANDIDATE_B_TEST_EVASION,
    CANDIDATE_C_IMPORT_TIME_SIDE_EFFECT,
    CANDIDATE_D_CONFTEST_PAYLOAD,
    CANDIDATE_E_OVERWRITE_ATTEMPT,
    CANDIDATE_F_RESOURCE_EXHAUSTION,
)
from .hardened_verifier import HardenedQualityGate, HardenedVerificationRecord
from .mock_github_fixture import (
    DEFAULT_COMMITTED_SHA,
    DEFAULT_PARENT_SHA,
    GitHubContentsProviderFixture,
    ProviderFixtureState,
    build_reviewed_create,
)
from .mock_probe_server import MockProbeServer
from .problem_setup import (
    BUGGY_RATE_LIMITER,
    CORRECT_RATE_LIMITER,
    INDEPENDENT_VERIFICATION_TESTS,
    WORKSPACE_TESTS,
    create_problem_workspace,
)
from .quality_gate import (
    IndependentQualityGate,
    OperatorApprovalAuthority,
    VerificationRecord,
    generate_signed_evidence_record,
    verify_evidence_signature,
)

__all__ = [
    "BUGGY_RATE_LIMITER",
    "CANDIDATE_A_DORMANT_BACKDOOR",
    "CANDIDATE_B_TEST_EVASION",
    "CANDIDATE_C_IMPORT_TIME_SIDE_EFFECT",
    "CANDIDATE_D_CONFTEST_PAYLOAD",
    "CANDIDATE_E_OVERWRITE_ATTEMPT",
    "CANDIDATE_F_RESOURCE_EXHAUSTION",
    "CORRECT_RATE_LIMITER",
    "DEFAULT_COMMITTED_SHA",
    "DEFAULT_PARENT_SHA",
    "GitHubContentsProviderFixture",
    "HardenedQualityGate",
    "HardenedVerificationRecord",
    "INDEPENDENT_VERIFICATION_TESTS",
    "IndependentQualityGate",
    "MockProbeServer",
    "OperatorApprovalAuthority",
    "ProviderFixtureState",
    "WORKSPACE_TESTS",
    "build_reviewed_create",
    "create_problem_workspace",
    "generate_signed_evidence_record",
    "verify_evidence_signature",
]
