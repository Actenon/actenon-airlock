"""EXPERIMENTAL evaluation harness: fixtures, problem setups and test runners.

Nothing here is a production or release component. Candidate code may only be
executed inside ContainerQualityGate; see evaluations/CORRECTIONS.md.
"""

from .candidates import (
    CANDIDATE_A_DORMANT_BACKDOOR,
    CANDIDATE_B_TEST_EVASION,
    CANDIDATE_C_IMPORT_TIME_SIDE_EFFECT,
    CANDIDATE_D_CONFTEST_PAYLOAD,
    CANDIDATE_E_OVERWRITE_ATTEMPT,
    CANDIDATE_F_RESOURCE_EXHAUSTION,
)
from .hardened_verifier import ContainerQualityGate, ContainerVerificationRecord, IsolationError
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
    TESTS_FAILED,
    TESTS_PASSED,
    ApprovalRequest,
    HostExecutionRefused,
    IndependentQualityGate,
    OperatorApprovalAuthority,
    VerificationRecord,
    generate_signed_evidence_record,
    sign_approval_request,
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
    "ApprovalRequest",
    "ContainerQualityGate",
    "ContainerVerificationRecord",
    "HostExecutionRefused",
    "IsolationError",
    "TESTS_FAILED",
    "TESTS_PASSED",
    "VerificationRecord",
    "sign_approval_request",
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
