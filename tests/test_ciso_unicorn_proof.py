"""Tests for Phase C: The End-to-End Unicorn Smoke Test ("The 60-Second CISO Proof")."""

from __future__ import annotations

from pathlib import Path

from actenon_airlock import export_compliance_bundle, verify_ledger
from actenon_airlock.ciso_proof import RAW_STRIPE_SECRET, run_ciso_proof


def test_sixty_second_ciso_unicorn_proof(tmp_path: Path) -> None:
    result = run_ciso_proof(workspace=tmp_path)

    assert result["ok"] is True
    assert result["elapsed_seconds"] < 60.0

    # Stage 1: AIRLOCK AUTHORITY DIFF
    diff_text = result["stage_1_authority_diff"]
    assert "AIRLOCK AUTHORITY DIFF" in diff_text
    assert "+ database.delete production/customers [RESOLVED]" in diff_text
    assert "+ http.post api.stripe.com/v1/refunds [RESOLVED]" in diff_text

    # Stage 2: Bounded $500 Grant + Delegated Sub-Grants
    grants = result["stage_2_grants"]
    assert grants["parent_budget_usd"] == 500.0
    assert len(grants["sub_grants"]) == 2
    assert "database.delete:production/customers" in grants["allowed_scopes"]
    assert "http.post:api.stripe.com/v1/refunds" in grants["allowed_scopes"]

    # Stage 3: Autonomous Execution (<= $500) + Read-Only Witness Reconciliation
    execution = result["stage_3_execution"]
    assert execution["secret_leaked"] is False
    assert execution["witness_reconciled"]["id"] == "re_ch_1001"
    assert execution["witness_reconciled"]["amount"] == 120
    assert execution["witness_reconciled"]["status"] == "succeeded"

    # Stage 4: All 5 Adversarial Attacks Deterministically Refused
    refusals = result["stage_4_refusals"]
    assert refusals["attack_1_parameter_tampering"]["refusal_code"] == "PARAMETER_MISMATCH"
    assert refusals["attack_2_replay_attack"]["refusal_code"] == "REPLAY_DETECTED"
    assert refusals["attack_3_delegated_budget_overflow"]["refusal_code"] == "BUDGET_EXCEEDED"
    assert refusals["attack_4_scope_escalation"]["refusal_code"] == "SCOPE_VIOLATION"
    assert refusals["attack_5_kill_switch"]["refusal_code"] == "AUTHORITY_REVOKED"

    # Stage 5: Hash-Chained Audit Ledger Proof & Compliance Bundle
    candidate_dir = tmp_path / "candidate_workflow"
    ledger = verify_ledger(candidate_dir)
    assert ledger["ok"] is True
    assert ledger["receipts"] == 6
    assert ledger["verified"] == 6

    bundle = export_compliance_bundle(candidate_dir)
    assert bundle["schema"] == "actenon-airlock/compliance-bundle/v1"
    assert bundle["ledger"]["ok"] is True
    assert bundle["ledger"]["allow_receipts"] == 1
    assert bundle["ledger"]["deny_refusals"] == 5
    assert RAW_STRIPE_SECRET not in str(bundle)
