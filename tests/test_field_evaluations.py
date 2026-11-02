"""Regression tests for the EXPERIMENTAL field-evaluation harness.

None of these tests executes candidate code on the host. The original versions
ran candidates with pytest and exec() in this process, which fired candidate C's
import-time network beacon wherever the suite ran (evaluations/CORRECTIONS.md).
Container-backed checks live in evaluations/tests and run in the protected CI
job, which has Docker.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import re
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluations.harness.candidates import (
    CANDIDATE_A_DORMANT_BACKDOOR,
    CANDIDATE_B_TEST_EVASION,
    CANDIDATE_C_IMPORT_TIME_SIDE_EFFECT,
)
from evaluations.harness.hardened_verifier import ContainerQualityGate, IsolationError
from evaluations.harness.mock_github_fixture import (
    DEFAULT_COMMITTED_SHA,
    DEFAULT_PARENT_SHA,
    GitHubContentsProviderFixture,
    ProviderFixtureState,
    build_reviewed_create,
)
from evaluations.harness.problem_setup import CORRECT_RATE_LIMITER
from evaluations.harness.quality_gate import (
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

ROOT = Path(__file__).resolve().parents[1]
WITHDRAWN_SECRET = b"actenon_trusted_verifier_internal_hmac_secret_2026"


def test_github_contents_provider_fixture_consequence_flow():
    """Verify GitHub Contents mock fixture handles preflight, PUT mutation, and readback."""
    state = ProviderFixtureState(
        owner="acme",
        repo="disposable-target",
        branch="main",
        path="security/audit_manifest.json",
        expected_parent_sha=DEFAULT_PARENT_SHA,
    )
    fixture = GitHubContentsProviderFixture(state)

    # 1. GET repo metadata
    repo_req = httpx.Request("GET", "https://api.github.com/repos/acme/disposable-target")
    repo_resp = fixture(repo_req)
    assert repo_resp.status_code == 200
    assert repo_resp.json()["id"] == 78901

    # 2. GET branch ref
    ref_req = httpx.Request(
        "GET", "https://api.github.com/repos/acme/disposable-target/git/ref/heads/main"
    )
    ref_resp = fixture(ref_req)
    assert ref_resp.status_code == 200
    assert ref_resp.json()["object"]["sha"] == DEFAULT_PARENT_SHA

    # 3. Preflight GET contents check (must be 404 at parent commit)
    check_req = httpx.Request(
        "GET",
        f"https://api.github.com/repos/acme/disposable-target/contents/security/audit_manifest.json?ref={DEFAULT_PARENT_SHA}",
    )
    check_resp = fixture(check_req)
    assert check_resp.status_code == 404

    # 4. PUT file creation mutation
    content = b'{"status": "approved"}\n'
    put_body = {
        "branch": "main",
        "message": "deploy approved audit manifest",
        "content": base64.b64encode(content).decode(),
    }
    put_req = httpx.Request(
        "PUT",
        "https://api.github.com/repos/acme/disposable-target/contents/security/audit_manifest.json",
        json=put_body,
    )
    put_resp = fixture(put_req)
    assert put_resp.status_code == 201
    assert state.current_head_sha == DEFAULT_COMMITTED_SHA
    assert state.files["security/audit_manifest.json"] == content

    # 5. Readback contents at new head
    read_req = httpx.Request(
        "GET",
        f"https://api.github.com/repos/acme/disposable-target/contents/security/audit_manifest.json?ref={DEFAULT_COMMITTED_SHA}",
    )
    read_resp = fixture(read_req)
    assert read_resp.status_code == 200
    assert base64.b64decode(read_resp.json()["content"]) == content


def test_github_fixture_ambiguous_settlement_simulation():
    """Verify fixture simulates dropped ACK causing ambiguous settlement."""
    state = ProviderFixtureState(lose_ack_on_put=True)
    fixture = GitHubContentsProviderFixture(state)

    put_body = {
        "branch": "main",
        "message": "deploy approved manifest",
        "content": base64.b64encode(b"manifest content").decode(),
    }
    put_req = httpx.Request(
        "PUT",
        "https://api.github.com/repos/acme/disposable-target/contents/security/audit_manifest.json",
        json=put_body,
    )

    try:
        fixture(put_req)
        assert False, "Should have raised ReadTimeout"
    except httpx.ReadTimeout:
        # Mutation occurred on provider, but ACK was severed
        assert state.files["security/audit_manifest.json"] == b"manifest content"
        assert len(state.calls) == 1


def test_reviewed_create_helper():
    """Verify build_reviewed_create populates expected consequence profile."""
    content = b"hello audit"
    rev = build_reviewed_create(
        owner="org",
        repo="repo",
        branch="main",
        path="file.txt",
        content_bytes=content,
        commit_message="commit",
        expected_parent_commit=DEFAULT_PARENT_SHA,
    )
    assert rev.content_sha256 == hashlib.sha256(content).hexdigest()
    assert rev.owner == "org"
    assert rev.repo == "repo"
    assert rev.expected_parent_sha == DEFAULT_PARENT_SHA


def _record(path: Path, verdict: str = TESTS_PASSED) -> VerificationRecord:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return VerificationRecord("rate_limiter.py", digest, "", "", True, 0, 0, verdict, 0.0, [])


@pytest.fixture
def candidate(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "executed"
    path = tmp_path / "rate_limiter.py"
    path.write_text(f"open({str(marker)!r}, 'w').close()\n" + CORRECT_RATE_LIMITER)
    return path, marker


def test_host_quality_gate_refuses_and_never_executes_candidate(candidate) -> None:
    path, marker = candidate
    with pytest.raises(HostExecutionRefused):
        IndependentQualityGate().audit_and_verify(path, workspace_dir=path.parent)
    assert not marker.exists()


def test_no_published_signing_secret_or_shared_mac_in_harness() -> None:
    for py in (ROOT / "evaluations" / "harness").glob("*.py"):
        text = py.read_text()
        assert "hmac.new(" not in text, py
        assert WITHDRAWN_SECRET.decode() not in text, py


def test_evidence_verifies_only_against_the_trusted_key(candidate) -> None:
    path, _ = candidate
    key = Ed25519PrivateKey.generate()
    trusted = public_key_b64(key)
    record = {"candidate_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "v": TESTS_PASSED}
    evidence = generate_signed_evidence_record(record, key)
    assert verify_evidence_signature(evidence, trusted)

    tampered = json.loads(json.dumps(evidence))
    tampered["record"]["v"] = TESTS_FAILED
    assert not verify_evidence_signature(tampered, trusted)

    # An attacker's own key and signature, embedded in the record, are ignored.
    attacker = generate_signed_evidence_record(record, Ed25519PrivateKey.generate())
    assert not verify_evidence_signature(attacker, trusted)

    # The withdrawn scheme's forgery no longer verifies.
    mac = hmac.new(WITHDRAWN_SECRET, json.dumps(record, sort_keys=True).encode(), hashlib.sha256)
    assert not verify_evidence_signature({"record": record, "signature": mac.hexdigest()}, trusted)


def test_passing_tests_never_approve_without_operator_signature(candidate) -> None:
    path, _ = candidate
    operator = Ed25519PrivateKey.generate()
    verifier = Ed25519PrivateKey.generate()
    authority = OperatorApprovalAuthority(public_key_b64(operator))
    record = _record(path)
    evidence = generate_signed_evidence_record(
        {"candidate_sha256": record.candidate_sha256}, verifier
    )

    request, message = authority.request_approval(path, record, evidence)
    assert request is not None and "not approval" in message

    for wrong in (Ed25519PrivateKey.generate(), verifier):
        ok, _ = authority.accept_signed_approval(
            request, sign_approval_request(request, wrong), path
        )
        assert not ok
    # An evidence signature cannot be replayed as an approval (domain separation).
    ok, _ = authority.accept_signed_approval(request, evidence["signature"], path)
    assert not ok

    signature = sign_approval_request(request, operator)
    assert authority.accept_signed_approval(request, signature, path)[0]

    other, _ = authority.request_approval(path, record, evidence, expected_repo="acme/other")
    assert not authority.accept_signed_approval(other, signature, path)[0]

    path.write_text(CANDIDATE_A_DORMANT_BACKDOOR)
    assert authority.accept_signed_approval(request, signature, path) == (
        False,
        "Candidate changed after the operator signed",
    )


def test_approval_requests_refuse_failed_substituted_or_unbound_evidence(candidate) -> None:
    path, _ = candidate
    authority = OperatorApprovalAuthority(public_key_b64(Ed25519PrivateKey.generate()))
    record = _record(path)
    key = Ed25519PrivateKey.generate()
    evidence = generate_signed_evidence_record({"candidate_sha256": record.candidate_sha256}, key)

    assert authority.request_approval(path, _record(path, TESTS_FAILED), evidence)[0] is None
    unbound = generate_signed_evidence_record({"candidate_sha256": "0" * 64}, key)
    assert authority.request_approval(path, record, unbound)[0] is None
    substitute = path.with_name("substitute.py")
    substitute.write_text(CANDIDATE_A_DORMANT_BACKDOOR)
    request, message = authority.request_approval(substitute, record, evidence)
    assert request is None and "TOCTOU" in message


def test_adversarial_candidates_are_inspected_statically_not_executed() -> None:
    for source in (CANDIDATE_A_DORMANT_BACKDOOR, CANDIDATE_B_TEST_EVASION):
        assert any(
            isinstance(n, ast.ClassDef) and n.name == "TokenBucket" for n in ast.parse(source).body
        )
    beacon = ast.parse(CANDIDATE_C_IMPORT_TIME_SIDE_EFFECT)
    module_level_calls = [
        node.func.attr
        for stmt in beacon.body
        if isinstance(stmt, ast.Try)
        for node in ast.walk(stmt)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert (
        "urlopen" in module_level_calls
    )  # fires at import, which is why it is never imported here


def test_historical_runners_refuse_host_execution() -> None:
    guard = re.compile(r'if not \(_os\.path\.exists\("/\.dockerenv"\)')
    runners = [
        p for p in (ROOT / "evaluations" / "suites").rglob("*.py") if guard.search(p.read_text())
    ]
    assert len(runners) == 15
    for path in runners:
        body = ast.parse(path.read_text()).body
        body = body[1:] if isinstance(body[0], ast.Expr) else body
        first_if = next(i for i, stmt in enumerate(body) if isinstance(stmt, ast.If))
        assert all(isinstance(s, ast.Import) for s in body[:first_if]), path


def test_container_settings_must_match_before_start() -> None:
    gate = ContainerQualityGate("unused")
    good = {
        "Image": "sha256:x",
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"], "CapAdd": None, "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": 128, "Memory": 512 * 1024 * 1024, "NanoCpus": 1_000_000_000,
            "Tmpfs": {"/tmp": "rw,noexec"},
        },
        "Config": {"User": "65534:65534"},
        "Mounts": [
            {"Destination": "/candidate", "RW": False},
            {"Destination": "/trusted", "RW": False},
            {"Destination": "/out", "RW": True},
        ],
    }  # fmt: skip
    mounts = {"/candidate": False, "/trusted": False, "/out": True}
    assert gate._check(good, "sha256:x", mounts)["network_mode"] == "none"
    for mutate in (
        lambda c: c["HostConfig"].update(NetworkMode="bridge"),
        lambda c: c["HostConfig"].update(ReadonlyRootfs=False),
        lambda c: c["HostConfig"].update(CapAdd=["NET_RAW"]),
        lambda c: c["HostConfig"].update(SecurityOpt=[]),
        lambda c: c["HostConfig"].update(PidsLimit=0),
        lambda c: c["Config"].update(User="0:0"),
        lambda c: c["Mounts"][1].update(RW=True),
        lambda c: c.update(Image="sha256:other"),
    ):
        changed = json.loads(json.dumps(good))
        mutate(changed)
        with pytest.raises(IsolationError):
            gate._check(changed, "sha256:x", mounts)


def test_evaluations_are_not_shipped_or_imported_by_airlock() -> None:
    assert (
        '[tool.setuptools.packages.find]\nwhere = ["src"]' in (ROOT / "pyproject.toml").read_text()
    )
    for py in (ROOT / "src" / "actenon_airlock").rglob("*.py"):
        assert "evaluations" not in py.read_text(), py
