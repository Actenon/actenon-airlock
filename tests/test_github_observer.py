"""Host observer tests using real ledger/proofs and synthetic provider readback.

No live GitHub mutation, useful-agent or containment pass is claimed here.
"""

import base64
import copy
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_github_protected_integration import (
    COMMIT,
    PARENT,
    PATCH,
    SECRET,
    ProviderFixture,
    approved_project,
    captured_broker,
    creation,
    protected_message,
    reviewed,
)

from actenon_airlock.common import AirlockError
from actenon_airlock.github_consequence import MAX_OBSERVATION_BYTES, project_create
from actenon_airlock.github_observer import _body_record, observe_github
from actenon_airlock.reconciliation import (
    apply_reconciliation,
    operator_identity,
    prepare_reconciliation,
    verify_observation,
)


@pytest.fixture
def held(tmp_path, monkeypatch, request):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    review = reviewed()
    state, current = approved_project(tmp_path, [review])
    private = Ed25519PrivateKey.generate()
    key_id, public = operator_identity(private)
    state.approve({**state.approved(), "reconciliation_keys": {key_id: public}})
    provider = ProviderFixture([review], lose_ack=getattr(request, "param", False))
    broker = captured_broker(state, current, provider)
    result = broker.handle(protected_message(review))
    effect_id = result.get("effect_id") or next(
        item["row"]["proof"]["extensions"]["effect"]["effect_id"]
        for item in state.verify_receipts()["rows"]
        if item["row"].get("stage") == "authorized"
    )
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"
    try:
        yield state, review, private, broker, effect_id, provider
    finally:
        broker.close()


class Readback:
    def __init__(self, review, *, fault=None):
        self.review = review
        self.fault = fault
        self.calls = []
        self.projected = project_create("PUT", review.contents_url, creation(review), review)

    def __call__(self, request):
        self.calls.append(request)
        assert request.method == "GET"  # Observation must never execute/retry.
        assert request.headers["Authorization"] == "Bearer " + SECRET
        r = self.review
        url = str(request.url)
        if self.fault == "timeout":
            raise httpx.ReadTimeout("must not save Authorization: " + SECRET, request=request)
        if self.fault == "oversized":
            return httpx.Response(200, content=b"x" * (MAX_OBSERVATION_BYTES + 1))
        if self.fault == "redirect":
            return httpx.Response(302, headers={"location": "https://other.example/"})
        if self.fault == "404":
            return httpx.Response(404, json={"message": "Not Found"})
        if url == r.repository_url:
            value = {
                "id": 999 if self.fault == "repo" else r.repo_id,
                "node_id": r.repo_node_id,
                "full_name": f"{r.owner}/{r.repo}",
                "url": r.repository_url,
            }
            if self.fault == "credential_echo":
                value["irrelevant"] = SECRET
        elif url == r.branch_commit_url:
            value = {
                "sha": "c" * 40 if self.fault == "ack" else COMMIT,
                "url": r.repository_url + "/commits/" + COMMIT,
                "commit": {"message": r.message},
                "parents": [{"sha": "d" * 40 if self.fault == "parent" else PARENT}],
                "files": [
                    {"filename": r.path, "status": "added", "sha": self.projected.git_blob_sha1}
                ],
            }
            if self.fault == "extra_file":
                value["files"].append({"filename": "unexpected", "status": "added"})
        elif url == r.contents_at(COMMIT):
            data = b"different" if self.fault == "content" else PATCH
            value = {
                "type": "file",
                "path": r.path,
                "name": r.path.rsplit("/", 1)[-1],
                "encoding": "base64",
                "content": base64.b64encode(data).decode(),
                "sha": self.projected.git_blob_sha1,
                "size": len(data),
            }
        else:
            raise AssertionError("Unreviewed observation target")
        return httpx.Response(200, json=value)


def observe(held, *, fault=None):
    state, review, private, _, effect_id, _ = held
    provider = Readback(review, fault=fault)
    with httpx.Client(transport=httpx.MockTransport(provider)) as client:
        result = observe_github(state, effect_id, private, client=client)
    return result, provider


def artifact(result):
    path = Path(result["observation_path"])
    assert path.stat().st_mode & 0o777 == 0o600
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == result["observation_hash"]
    assert SECRET.encode() not in raw
    value = json.loads(raw)
    for item in value["observations"]:
        if "body_base64" in item:
            body = base64.b64decode(item["body_base64"], validate=True)
            assert SECRET.encode() not in body
            assert hashlib.sha256(body).hexdigest() == item["body_sha256"]
    return value


def test_exact_readback_signs_but_never_settles_or_retries(held):
    state, review, private, broker, effect_id, initial = held
    before = prepare_reconciliation(state, effect_id)
    journal_before = state.receipts_path.read_bytes()
    result, provider = observe(held)
    assert result["outcome"] == "COMMITTED"
    assert result["causal_attribution"] == "not_proven"
    assert result["provider_dispatched"] is False
    assert [(r.method, str(r.url)) for r in provider.calls] == [
        ("GET", review.repository_url),
        ("GET", review.branch_commit_url),
        ("GET", review.contents_at(COMMIT)),
    ]
    assert prepare_reconciliation(state, effect_id) == before
    assert state.receipts_path.read_bytes() == journal_before
    assert len(initial.mutations) == 1
    evidence = artifact(result)
    assert evidence["request"] == before
    assert evidence["acknowledged_commit"] == COMMIT
    assert evidence["github_profile"]["exclusive_writer"] is True
    verified = verify_observation(
        result["envelope"],
        json.loads((state.path / "approved.json").read_text()),
        json.loads((state.path / "public-key.json").read_text())["key"],
        at=datetime.now(UTC),
    )
    assert verified["outcome"] == "COMMITTED"
    assert verified["evidence_hash"] == result["observation_hash"]
    settled = apply_reconciliation(state, result["envelope"])
    assert settled["outcome"] == "COMMITTED"
    assert broker.store.get_effect(effect_id)[-1]["state"] == "COMMITTED"
    assert not broker.handle(protected_message(review))["ok"]
    assert len(initial.mutations) == 1
    terminal = broker.store.get_effect(effect_id)
    apply_reconciliation(state, result["envelope"])
    assert broker.store.get_effect(effect_id) == terminal


@pytest.mark.parametrize("held", [True], indirect=True)
def test_lost_ack_is_resolved_only_by_anchored_exact_provider_state(held):
    result, provider = observe(held)
    assert result["outcome"] == "COMMITTED"
    assert len(provider.calls) == 3
    assert artifact(result)["acknowledged_commit"] is None
    assert prepare_reconciliation(held[0], held[4])["prior_state"] == "AMBIGUOUS"


@pytest.mark.parametrize(
    "fault",
    ["timeout", "oversized", "redirect", "404", "repo", "ack", "parent", "extra_file", "content"],
)
def test_failed_readback_remains_ambiguous_without_envelope_or_state_change(held, fault):
    state, _, _, _, effect_id, initial = held
    before = prepare_reconciliation(state, effect_id)
    journal_before = state.receipts_path.read_bytes()
    result, provider = observe(held, fault=fault)
    assert result["outcome"] == "AMBIGUOUS"
    assert "envelope" not in result
    assert prepare_reconciliation(state, effect_id) == before
    assert state.receipts_path.read_bytes() == journal_before
    assert len(initial.mutations) == 1
    assert all(r.method == "GET" for r in provider.calls)
    artifact(result)


def test_current_operator_authority_precedes_credential_or_network_access(held, monkeypatch):
    state, _, _, _, effect_id, _ = held
    actual_get = os.environ.get

    def guarded_get(key, *args):
        assert key not in {"GITHUB_TOKEN", "GH_TOKEN"}
        return actual_get(key, *args)

    monkeypatch.setattr(os.environ, "get", guarded_get)
    with pytest.raises(AirlockError, match="not authorized"):
        observe_github(state, effect_id, Ed25519PrivateKey.generate(), client=object())


def test_revoked_observer_cannot_observe(held, monkeypatch):
    state, _, private, _, effect_id, _ = held
    state.approve({**state.approved(), "reconciliation_keys": {}})
    with pytest.raises(AirlockError, match="not authorized"):
        observe_github(state, effect_id, private, client=object())


def test_missing_credential_preserves_ambiguity_and_does_not_use_client(held, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN")
    state, _, private, _, effect_id, _ = held
    result = observe_github(state, effect_id, private, client=object())
    assert result["outcome"] == "AMBIGUOUS" and "envelope" not in result
    assert artifact(result)["reason"] == "credential_unavailable"


def test_original_review_not_changed_current_profile_controls_readback(held):
    state = held[0]
    approval = state.approved()
    approval["protected_github"][0]["review"]["expected_parent_sha"] = "e" * 40
    state.approve(approval)
    result, _ = observe(held)
    assert result["outcome"] == "COMMITTED"
    assert artifact(result)["github_profile"]["review"]["expected_parent_sha"] == PARENT


def _rewrite_signed_journal(state, mutate):
    # Simulate a historical trusted receipt writer, not an unprivileged attacker.
    rows = [item["row"] for item in state.verify_receipts()["rows"]]
    state.receipts_path.unlink()
    for row in rows:
        row.pop("signature")
        if row.get("stage") == "authorized":
            mutate(row)
        state.receipt(row)
    assert state.verify_receipts()["ok"]


@pytest.mark.parametrize("change", ["missing_profile", "changed_body", "changed_action_hash"])
def test_missing_or_unbound_original_request_never_uses_network(held, change):
    state, _, private, _, effect_id, _ = held

    def mutate(row):
        if change == "missing_profile":
            row.pop("github_profile")
        elif change == "changed_body":
            row["intent"]["action"]["parameters"]["github_body"] = base64.b64encode(b"{}").decode()
        else:
            row["proof"]["action_hash"]["value"] = "e" * 64

    _rewrite_signed_journal(state, mutate)
    with pytest.raises(AirlockError, match="does not match"):
        observe_github(state, effect_id, private, client=object())


def test_receipt_signature_tampering_blocks_observation_before_network(held):
    state, _, private, _, effect_id, _ = held
    value = state.receipts_path.read_text().replace('"decision":"ALLOW"', '"decision":"DENY"', 1)
    state.receipts_path.write_text(value)
    with pytest.raises(AirlockError, match="journal is invalid"):
        observe_github(state, effect_id, private, client=object())


def test_credential_echo_is_hash_only_in_owner_only_evidence(held):
    result, _ = observe(held, fault="credential_echo")
    assert result["outcome"] == "COMMITTED"
    first = artifact(result)["observations"][0]
    assert first["body_redacted"] == "active_credential_detected"
    assert "body_base64" not in first


def test_mutated_signed_observation_cannot_settle(held):
    state, _, _, broker, effect_id, _ = held
    result, _ = observe(held)
    tampered = copy.deepcopy(result["envelope"])
    tampered["payload"]["evidence_hash"] = "f" * 64
    with pytest.raises(AirlockError):
        apply_reconciliation(state, tampered)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"


def test_base64_credential_content_is_hash_only():
    body = json.dumps({"content": base64.b64encode(b"prefix" + SECRET.encode()).decode()}).encode()
    for creation_body in (True, False):
        record = _body_record(body, SECRET.encode(), content=creation_body)
        assert "body_base64" not in record
        assert record["body_redacted"] == "active_credential_detected"
        assert record["body_sha256"] == hashlib.sha256(body).hexdigest()
