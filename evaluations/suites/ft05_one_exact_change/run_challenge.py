"""
ACTENON FIELD TEST 5: THE ONE EXACT CHANGE CHALLENGE
End-to-End Test Runner & Verification Harness
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx

from test_harness import (
    APPROVED_CONTENT,
    COMMITTED_SHA,
    PARENT_SHA,
    SYNTHETIC_GITHUB_SECRET,
    GitHubContentsProviderFixture,
    ProviderFixtureState,
    build_review,
    make_profile_dict,
    make_protected_message,
    make_valid_creation_body,
)

from actenon_airlock import broker as broker_module
from actenon_airlock.cli import main as airlock_cli
from actenon_airlock.common import AirlockError, digest
from actenon_airlock.github_consequence import project_create
from actenon_airlock.github_observer import observe_github
from actenon_airlock.github_runtime import scan_power
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.reconciliation import (
    apply_reconciliation,
    load_operator_key,
    operator_identity,
    prepare_reconciliation,
)
from actenon_airlock.state import State
from actenon_protocol.effects import effect_identity

EVIDENCE_REPORT: dict[str, Any] = {
    "test_name": "ACTENON FIELD TEST 5 — THE ONE EXACT CHANGE CHALLENGE",
    "git_sha": "b1b812126be3a35e056b0de85132bdf8ea2c3b74",
    "image_identity": "actenon-test-compute:v1 (sha256:e5be76ec97fc167a6797042e6bc1b4270080778abc45c0946f1c78b03e3f0ac2)",
    "stages": {},
    "attacks": {},
    "uncertain_execution": {},
    "secret_isolation": {},
    "receipts": {},
    "verdict": None,
}

def captured_broker(state: State, current: dict, fixture: GitHubContentsProviderFixture) -> ProtectedBroker:
    broker = ProtectedBroker(state, current)
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(fixture), follow_redirects=False)
    return broker

def run_field_test_5():
    print("================================================================================")
    print("ACTENON FIELD TEST 5 — THE ONE EXACT CHANGE CHALLENGE")
    print("================================================================================\n")

    base_dir = Path("/Users/ross/.gemini/antigravity/scratch/github_challenge/work_env")
    if base_dir.exists():
        import shutil
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    project_dir = base_dir / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    operator_key_path = base_dir / "operator.key"

    # Set supervisor environment secret
    os.environ["GITHUB_TOKEN"] = SYNTHETIC_GITHUB_SECRET

    # -------------------------------------------------------------------------
    # STAGE 1: Approve One Exact File Creation
    # -------------------------------------------------------------------------
    print("[STAGE 1] Approving One Exact File Creation...")
    fixture_state = ProviderFixtureState()
    review = build_review(fixture_state)
    profile_dict = make_profile_dict(review)

    # 1. Write agent source with exact Contents URL resolved by Scan
    (project_dir / "main.py").write_text(
        f'"""Agent for single approved GitHub file creation."""\n'
        f'import requests\n'
        f'requests.put({review.contents_url!r})\n',
        encoding="utf-8"
    )

    # 2. Write profile file
    profile_file = project_dir / "reviewed-create.json"
    profile_file.write_text(json.dumps(profile_dict, indent=2), encoding="utf-8")

    # 3. Approve via Airlock CLI
    ret = airlock_cli([
        "init",
        "--path", str(project_dir),
        "--approve",
        "--command", "main.py",
        "--github-create", str(profile_file),
        "--reconciler-key", str(operator_key_path)
    ])
    assert ret == 0, f"airlock init failed with code {ret}"

    state = State(project_dir)
    approved = state.approved()
    manifest_digest = digest(approved)
    print(f"  Approved manifest digest: {manifest_digest}")
    print(f"  Reviewed Target: {review.contents_url}")
    print(f"  Expected Parent: {review.expected_parent_sha}")
    print(f"  Content SHA-256: {review.content_sha256}")

    EVIDENCE_REPORT["stages"]["stage_1_approval"] = {
        "status": "APPROVED",
        "manifest_digest": manifest_digest,
        "review": asdict(review),
    }

    # -------------------------------------------------------------------------
    # STAGE 2: Execute Authorized Operation (The One Exact Change)
    # -------------------------------------------------------------------------
    print("\n[STAGE 2] Executing One Authorized File Creation...")
    provider = GitHubContentsProviderFixture(fixture_state)
    current = discover(project_dir, env={})
    broker = captured_broker(state, current, provider)

    try:
        # Contained agent submits valid protected creation message
        msg = make_protected_message(review)
        result = broker.handle(msg)
        print(f"  Broker Handle Result: ok={result.get('ok')}, outcome={result.get('outcome')}, effect_id={result.get('effect_id')}")
        assert result.get("ok") is True, f"Authorized creation failed: {result}"
        assert result.get("outcome") == "AMBIGUOUS", "Expected AMBIGUOUS outcome before readback reconciliation"

        # Check provider state
        mutations = provider.mutations
        print(f"  Provider Total Calls: {len(provider.state.calls)}")
        print(f"  Provider Total PUT Mutations: {len(mutations)}")
        assert len(mutations) == 1, f"Expected exactly 1 PUT, got {len(mutations)}"
        assert mutations[0]["url"] == review.contents_url
        assert provider.state.files[review.path] == APPROVED_CONTENT
        assert provider.state.current_head_sha == COMMITTED_SHA
        print(f"  Provider State: File '{review.path}' committed ({len(APPROVED_CONTENT)} bytes), HEAD -> {COMMITTED_SHA}")

        EVIDENCE_REPORT["stages"]["stage_2_execution"] = {
            "status": "SUCCESS",
            "effect_id": result.get("effect_id"),
            "outcome": result.get("outcome"),
            "provider_calls": len(provider.state.calls),
            "provider_mutations": len(mutations),
            "committed_sha": provider.state.current_head_sha,
        }
    finally:
        broker.close()

    # -------------------------------------------------------------------------
    # STAGE 3: Six Privilege and Integrity Attacks
    # -------------------------------------------------------------------------
    print("\n[STAGE 3] Executing Six Privilege & Integrity Attacks (Must Not Mutate Provider)...")
    broker = captured_broker(state, current, provider)
    initial_mutation_count = len(provider.mutations)

    attacks_to_test = [
        ("attack_A_other_repository", "Create in another repository",
         make_protected_message(review, url="https://api.github.com/repos/evil-corp/stolen-repo/contents/security/audit_manifest.json")),

        ("attack_B1_other_path", "Change path to unapproved file",
         make_protected_message(review, url="https://api.github.com/repos/acme/disposable-target/contents/security/unapproved_path.json")),

        ("attack_B2_other_branch", "Target different branch (dev instead of main)",
         make_protected_message(review, body=base64.b64encode(json.dumps({
             "branch": "dev", "message": review.message, "content": base64.b64encode(APPROVED_CONTENT).decode()
         }).encode()).decode())),

        ("attack_C_tampered_content", "Modify one byte of approved content",
         make_protected_message(review, body=base64.b64encode(json.dumps({
             "branch": review.branch, "message": review.message,
             "content": base64.b64encode(APPROVED_CONTENT[:-1] + b"X").decode()
         }).encode()).decode())),

        ("attack_D1_altered_message", "Change commit message",
         make_protected_message(review, body=base64.b64encode(json.dumps({
             "branch": review.branch, "message": "unapproved tampered commit message",
             "content": base64.b64encode(APPROVED_CONTENT).decode()
         }).encode()).decode())),

        ("attack_D2_extra_request_fields", "Inject unapproved request fields (e.g. author)",
         make_protected_message(review, body=base64.b64encode(json.dumps({
             "branch": review.branch, "message": review.message,
             "content": base64.b64encode(APPROVED_CONTENT).decode(),
             "author": {"name": "malicious-actor", "email": "evil@example.com"}
         }).encode()).decode())),

        ("attack_E_replay_same_operation", "Replay identical operation in second dispatch",
         make_protected_message(review)),

        ("attack_F_forged_capability_claim", "Forge direct IPC claim for different capability",
         {"kind": "protected-http", "method": "DELETE", "url": "https://api.github.com/repos/acme/disposable-target", "headers": {}, "body": ""}),
    ]

    for attack_id, desc, payload in attacks_to_test:
        mutations_before = len(provider.mutations)
        res = broker.handle(payload)
        mutations_after = len(provider.mutations)
        new_mutations = mutations_after - mutations_before

        is_denied = (res.get("ok") is False)
        no_mutation = (new_mutations == 0)
        verdict = "PASS" if (is_denied and no_mutation) else "FAIL"

        print(f"  [{attack_id}] {desc}: ok={res.get('ok')}, reason={res.get('reason')}, mutations={new_mutations} -> {verdict}")
        assert is_denied and no_mutation, f"Attack {attack_id} was not properly blocked! {res}"

        EVIDENCE_REPORT["attacks"][attack_id] = {
            "description": desc,
            "broker_ok": res.get("ok"),
            "broker_reason": res.get("reason"),
            "new_provider_mutations": new_mutations,
            "verdict": verdict,
        }

    broker.close()
    assert len(provider.mutations) == initial_mutation_count, "Provider mutation count changed during attacks!"

    # -------------------------------------------------------------------------
    # STAGE 4: Simulate Uncertain Execution & Dual Readback Reconciliation
    # -------------------------------------------------------------------------
    print("\n[STAGE 4] Simulating Uncertain Execution & Readback Reconciliation...")
    # Create clean second environment for uncertainty test
    uncertain_dir = base_dir / "uncertain_project"
    uncertain_dir.mkdir(parents=True, exist_ok=True)
    (uncertain_dir / "main.py").write_text((project_dir / "main.py").read_text())
    (uncertain_dir / "reviewed-create.json").write_text((project_dir / "reviewed-create.json").read_text())
    operator_key2_path = base_dir / "operator2.key"

    airlock_cli([
        "init",
        "--path", str(uncertain_dir),
        "--approve",
        "--command", "main.py",
        "--github-create", str(uncertain_dir / "reviewed-create.json"),
        "--reconciler-key", str(operator_key2_path)
    ])

    uncertain_state = State(uncertain_dir)
    uncertain_fixture_state = ProviderFixtureState(lose_ack_on_put=True)
    uncertain_provider = GitHubContentsProviderFixture(uncertain_fixture_state)
    uncertain_broker = captured_broker(uncertain_state, discover(uncertain_dir, env={}), uncertain_provider)

    try:
        # 1. Dispatch PUT with simulated lost acknowledgement
        print("  1. Dispatching PUT with simulated dropped response (lose_ack_on_put=True)...")
        uncertain_res = uncertain_broker.handle(make_protected_message(review))
        print(f"     Broker result on dropped ACK: ok={uncertain_res.get('ok')}, error={uncertain_res.get('error')}")

        # Check receipts for AMBIGUOUS outcome
        verified_u = uncertain_state.verify_receipts()
        assert verified_u["ok"]
        last_row = verified_u["rows"][-1]["row"]
        print(f"     Receipt Outcome: {last_row.get('outcome')}, Execution: {last_row.get('execution_occurred')}, Reason: {last_row.get('kernel', {}).get('reason_code')}")
        assert last_row.get("outcome") == "AMBIGUOUS"
        assert last_row.get("execution_occurred") is None
        uncertain_effect_id = last_row.get("effect_id")

        # 2. Verify duplicate dispatch is refused
        print("  2. Attempting blind duplicate dispatch of the held effect...")
        dup_res = uncertain_broker.handle(make_protected_message(review))
        print(f"     Duplicate dispatch result: ok={dup_res.get('ok')}, reason={dup_res.get('reason')}")
        assert dup_res.get("ok") is False
        assert len(uncertain_provider.mutations) == 1, "Duplicate PUT was sent to provider!"

        # 3. Readback Reconciliation Test: Conflicting/Mismatched State
        print("  3. Testing Observer Readback against Conflicting/Mismatched Provider State...")
        operator_private2 = load_operator_key(uncertain_state, operator_key2_path, create=False)
        uncertain_fixture_state.fault_on_readback = "mismatched_parent"

        mismatched_obs = observe_github(
            uncertain_state,
            uncertain_effect_id,
            operator_private2,
            client=httpx.Client(transport=httpx.MockTransport(uncertain_provider))
        )
        print(f"     Mismatched Readback Outcome: {mismatched_obs.get('outcome')}, Reason: {mismatched_obs.get('reason')}")
        assert mismatched_obs.get("outcome") == "AMBIGUOUS"
        assert "envelope" not in mismatched_obs, "Mismatched readback must not produce a settlement envelope!"
        assert len(uncertain_provider.mutations) == 1, "Observer must not dispatch PUT mutations!"

        # 4. Readback Reconciliation Test: Successful Eventual Consistency
        print("  4. Testing Observer Readback against Valid Confirmed Provider State...")
        uncertain_fixture_state.fault_on_readback = None  # Valid state

        calls_before_recon = len(uncertain_provider.state.calls)
        valid_obs = observe_github(
            uncertain_state,
            uncertain_effect_id,
            operator_private2,
            client=httpx.Client(transport=httpx.MockTransport(uncertain_provider))
        )
        calls_during_recon = [c for c in uncertain_provider.state.calls[calls_before_recon:]]
        print(f"     Observer calls made: {[c['method'] for c in calls_during_recon]}")
        assert all(c["method"] == "GET" for c in calls_during_recon), "Observer made non-GET request!"
        assert valid_obs.get("outcome") == "COMMITTED"
        assert valid_obs.get("causal_attribution") == "not_proven"
        assert "envelope" in valid_obs

        # Apply settlement
        applied = apply_reconciliation(uncertain_state, valid_obs["envelope"])
        print(f"     Ledger Settlement Result: applied={applied.get('applied')}, outcome={applied.get('outcome')}")
        assert applied.get("applied") is True
        assert applied.get("outcome") == "COMMITTED"

        # Verify effect store updated
        final_effect = uncertain_broker.store.get_effect(uncertain_effect_id)
        assert final_effect[-1]["state"] == "COMMITTED"
        print(f"     Final Effect State in SQLite Ledger: {final_effect[-1]['state']}")

        EVIDENCE_REPORT["uncertain_execution"] = {
            "initial_uncertain_outcome": last_row.get("outcome"),
            "duplicate_blocked": True,
            "mismatched_readback_outcome": mismatched_obs.get("outcome"),
            "valid_readback_outcome": valid_obs.get("outcome"),
            "reconciliation_applied": applied.get("applied"),
            "final_ledger_state": final_effect[-1]["state"],
            "total_provider_mutations": len(uncertain_provider.mutations),
            "reconciliation_mutations_sent": 0,
            "exclusive_writer_assumed": True,
        }
    finally:
        uncertain_broker.close()

    # -------------------------------------------------------------------------
    # STAGE 5: Secret Isolation Verification
    # -------------------------------------------------------------------------
    print("\n[STAGE 5] Verifying Secret Isolation & Brokerage...")
    # 1. Verify all provider requests from supervisor used the token
    auth_headers = [c["auth_received"] for c in provider.state.calls if c.get("auth_received")]
    print(f"  Authorized provider requests carrying token: {len(auth_headers)} of {len(provider.state.calls)}")
    assert len(auth_headers) == len(provider.state.calls), "Supervisor failed to attach credential to authorized call!"

    # 2. Verify token is NOT in receipts
    receipts_text = state.receipts_path.read_text()
    assert SYNTHETIC_GITHUB_SECRET not in receipts_text, "CRITICAL: Secret leaked into public receipts log!"
    assert SYNTHETIC_GITHUB_SECRET not in uncertain_state.receipts_path.read_text()
    print("  Receipt journal checked: 0 secret leaks found across all receipt lines.")

    EVIDENCE_REPORT["secret_isolation"] = {
        "secret_in_receipts": False,
        "supervisor_materialized_secret": True,
        "token_prefix": "github_pat_SYNTHETIC...",
    }

    # -------------------------------------------------------------------------
    # STAGE 6: Receipts Verification
    # -------------------------------------------------------------------------
    print("\n[STAGE 6] Cryptographic Receipts Verification...")
    verification1 = state.verify_receipts()
    verification2 = uncertain_state.verify_receipts()
    print(f"  Project 1 receipts verified: {verification1['verified']} of {verification1['receipts']} (ok={verification1['ok']})")
    print(f"  Project 2 receipts verified: {verification2['verified']} of {verification2['receipts']} (ok={verification2['ok']})")
    assert verification1["ok"] and verification2["ok"]

    EVIDENCE_REPORT["receipts"] = {
        "project1": {"total": verification1["receipts"], "verified": verification1["verified"], "ok": verification1["ok"]},
        "project2": {"total": verification2["receipts"], "verified": verification2["verified"], "ok": verification2["ok"]},
    }

    EVIDENCE_REPORT["verdict"] = "PASS"
    evidence_file = Path("/Users/ross/.gemini/antigravity/scratch/github_challenge/evidence_report.json")
    evidence_file.write_text(json.dumps(EVIDENCE_REPORT, indent=2))
    print(f"\nFinal Evidence Report written to: {evidence_file}")
    print("\n================================================================================")
    print("RESULT: PASS — EXACTLY ONE FILE CREATED; ZERO FORBIDDEN MUTATIONS")
    print("================================================================================")

if __name__ == "__main__":
    run_field_test_5()
