"""Tests for Phase C (Local Fixture CISO Proof) and Release Review Corrections (R1, R3, R4, R5)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from actenon_permit.model import DecisionOutcome

from actenon_airlock import export_compliance_bundle, verify_ledger
from actenon_airlock.ciso_proof import (
    RAW_STRIPE_SECRET,
    attribute_delegated_overflow,
    run_ciso_proof,
)
from actenon_airlock.state import State


def test_sixty_second_ciso_unicorn_proof(tmp_path: Path) -> None:
    result = run_ciso_proof(workspace=tmp_path)

    assert result["ok"] is True
    assert result["evidence_scope"] == "deterministic_local_fixture_demo"
    assert result["elapsed_seconds"] < 60.0

    # Stage 1: AIRLOCK AUTHORITY DIFF
    diff_text = result["stage_1_authority_diff"]
    assert "AIRLOCK AUTHORITY DIFF" in diff_text
    assert "+ database.delete production/customers [RESOLVED]" in diff_text
    assert "+ http.post api.stripe.com/v1/refunds [RESOLVED]" in diff_text

    # Stage 2: Bounded $500 Grant + Delegated Sub-Grants + Canonical Approval
    grants = result["stage_2_grants"]
    assert grants["parent_budget_usd"] == 500.0
    assert len(grants["sub_grants"]) == 2
    assert grants["approval_verified"] is True
    assert "database.delete:production/customers" in grants["allowed_scopes"]
    assert "http.post:api.stripe.com/v1/refunds" in grants["allowed_scopes"]

    # Stage 3: Autonomous Execution (<= $500) + Read-Only Witness Reconciliation
    execution = result["stage_3_execution"]
    assert execution["secret_leaked"] is False
    assert execution["secret_absent_from_serialized_outputs"] is True
    assert execution["witness_reconciled"]["id"] == "re_ch_1001"
    assert execution["witness_reconciled"]["amount"] == 120
    assert execution["witness_reconciled"]["status"] == "succeeded"

    # Stage 4: All 5 Adversarial Attacks Deterministically Refused
    refusals = result["stage_4_refusals"]
    assert refusals["attack_1_parameter_tampering"]["refusal_code"] == "PARAMETER_MISMATCH"
    assert refusals["attack_2_replay_attack"]["refusal_code"] == "REPLAY_DETECTED"
    assert refusals["attack_3_delegated_budget_overflow"]["refusal_code"] == "BUDGET_EXCEEDED"
    assert refusals["attack_3_delegated_budget_overflow"]["grant_id"] in grants["sub_grants"]
    assert refusals["attack_4_scope_escalation"]["refusal_code"] == "SCOPE_VIOLATION"
    assert refusals["attack_5_kill_switch"]["refusal_code"] == "AUTHORITY_REVOKED"

    # Stage 5: Hash-Chained Audit Ledger Proof & Compliance Bundle
    candidate_dir = tmp_path / "candidate_workflow"
    state = State(candidate_dir)
    # R3: Both state.approved() and state.checked_in_approval() succeed!
    assert state.approved()["schema"] == "actenon-airlock/authority/v1"
    assert state.checked_in_approval()["schema"] == "actenon-airlock/authority/v1"

    ledger = verify_ledger(candidate_dir)
    assert ledger["ok"] is True
    assert ledger["receipts"] == 6
    assert ledger["verified"] == 6
    assert ledger["chain_head_sha256"] is not None

    bundle = export_compliance_bundle(
        candidate_dir,
        expected_head_sha256=ledger["chain_head_sha256"],
    )
    assert bundle["schema"] == "actenon-airlock/compliance-bundle/v1"
    assert bundle["ok"] is True
    assert bundle["approval_verified"] is True
    assert bundle["approved_manifest"] is not None
    assert bundle["ledger"]["ok"] is True
    assert bundle["ledger"]["completeness"] == "anchored"
    assert bundle["ledger"]["allow_receipts"] == 1
    assert bundle["ledger"]["deny_refusals"] == 5
    assert bundle["controls"]["mapping_status"] == "draft_unvalidated_control_mapping"
    assert RAW_STRIPE_SECRET not in str(bundle)


def test_r3_export_compliance_bundle_fails_closed_on_invalid_approval_or_truncation(
    tmp_path: Path,
) -> None:
    """R3 & R5: export_compliance_bundle fails closed if approval is invalid or head digest mismatches."""
    run_ciso_proof(workspace=tmp_path)
    candidate_dir = tmp_path / "candidate_workflow"
    state = State(candidate_dir)

    # 1. Mismatched expected_head_sha256 (simulating tail truncation check) fails closed
    truncated_bundle = export_compliance_bundle(
        state,
        expected_head_sha256="0" * 64,
    )
    assert truncated_bundle["ok"] is False
    assert truncated_bundle["ledger"]["ok"] is False
    assert truncated_bundle["ledger"]["completeness"] == "truncated_or_mismatched"

    # 2. Tampering with .airlock/approved.json schema fails closed instead of silently returning ok=True
    (state.path / "approved.json").write_text(
        json.dumps({"schema": "actenon-airlock/manifest/v1", "powers": []}),
        encoding="utf-8",
    )
    bad_approval_bundle = export_compliance_bundle(state)
    assert bad_approval_bundle["approval_verified"] is False
    assert bad_approval_bundle["approved_manifest"] is None
    assert bad_approval_bundle["ok"] is False
    assert bad_approval_bundle["ledger"]["ok"] is False


def test_r4_attribute_delegated_overflow_attributes_actual_denied_grant() -> None:
    """R4: Delegated budget overflow refusal attributes the actual denied sub-grant in both thread orders."""
    allow_dec = SimpleNamespace(outcome=DecisionOutcome.ALLOW, failure_code=None, reason="ok")
    deny_dec = SimpleNamespace(
        outcome=DecisionOutcome.DENY,
        failure_code="BUDGET_EXCEEDED",
        reason="ancestor budget exceeded",
    )

    # Case 1: alpha denied, beta allowed
    gid_1, dec_1 = attribute_delegated_overflow(
        [("grant_alpha", deny_dec), ("grant_beta", allow_dec)]
    )
    assert gid_1 == "grant_alpha"
    assert dec_1 is deny_dec

    # Case 2: alpha allowed, beta denied
    gid_2, dec_2 = attribute_delegated_overflow(
        [("grant_alpha", allow_dec), ("grant_beta", deny_dec)]
    )
    assert gid_2 == "grant_beta"
    assert dec_2 is deny_dec


def test_r1_candidate_admission_reports_not_ready_without_real_agent_artifact(
    tmp_path: Path,
) -> None:
    """R1: check_candidate_admission reports NOT READY when real-agent acceptance has not run."""
    import importlib.util
    import sys

    script_path = Path(__file__).resolve().parents[1] / "scripts" / "check_candidate_admission.py"
    spec = importlib.util.spec_from_file_location("check_candidate_admission", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    repo_root = Path(__file__).resolve().parents[1]
    report = mod.evaluate_gate_matrix(repo_root, acceptance_evidence_dir=tmp_path / "missing")
    assert report["overall_status"] == "NOT READY"
    assert report["gates"]["G36_G37_real_coding_agent_acceptance"]["status"] == "BLOCKED"
    assert report["gates"]["G6_G29_released_package_coherence"]["status"] == "RELEASE_BLOCKED"
