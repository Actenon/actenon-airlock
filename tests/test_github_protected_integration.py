"""Real installed Permit/Kernel integration with synthetic GitHub HTTP observations.

No live account, provider truth, container boundary or useful-agent pass is claimed.
Only HTTP transport is replaced; grants, signatures, durable claims and receipts
use the actual integrated components.
"""

import base64
import copy
import hashlib
import json
from dataclasses import asdict

import httpx
import pytest
from actenon.models import ActionIntent
from actenon_permit.model import Action, DecisionOutcome
from actenon_protocol.effects import effect_identity

from actenon_airlock import broker as broker_module
from actenon_airlock.common import AirlockError
from actenon_airlock.github_consequence import ReviewedGitHubCreate, project_create
from actenon_airlock.github_runtime import PROFILE_SCHEMA, effect_descriptor, scan_power
from actenon_airlock.manifest import capability, discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State

PATCH = b"diff --git a/math.py b/math.py\n-return a - b\n+return a + b\n"
PARENT = "a" * 40
COMMIT = "b" * 40
SECRET = "fixture-only-github-token"
MODEL_URL = "https://api.openai.com/v1/chat/completions"


def reviewed(path="patches/fix.patch"):
    return ReviewedGitHubCreate(
        repo_id=123,
        repo_node_id="R_fixture",
        owner="acme",
        repo="disposable",
        branch="review",
        path=path,
        message="publish reviewed patch",
        content_sha256=hashlib.sha256(PATCH).hexdigest(),
        expected_parent_sha=PARENT,
    )


def signed_profile(review):
    return {
        "schema": PROFILE_SCHEMA,
        "review": asdict(review),
        "exclusive_writer": True,
        "credential_name": "GITHUB_TOKEN",
    }


def creation(review, **changes):
    value = {
        "branch": review.branch,
        "message": review.message,
        "content": base64.b64encode(PATCH).decode(),
    }
    value.update(changes)
    return json.dumps(value).encode()


def protected_message(review, **changes):
    message = {
        "kind": "protected-http",
        "method": "PUT",
        "url": review.contents_url,
        "body": base64.b64encode(creation(review)).decode(),
        "headers": {},
    }
    message.update(changes)
    return message


def approved_project(tmp_path, reviews, *, with_model=False):
    source = "import requests\n" + "".join(f"requests.put({r.contents_url!r})\n" for r in reviews)
    if with_model:
        source += "from openai import OpenAI\nOpenAI().chat.completions.create(model='test-model', messages=[])\n"
    (tmp_path / "agent.py").write_text(source)
    state = State(tmp_path)
    current = discover(tmp_path, env={})
    approval = {**current, "protected_github": [signed_profile(r) for r in reviews]}
    if with_model:
        approval["protected_model"] = {
            "provider": "openai",
            "models": ["test-model"],
            "max_output_tokens": 256,
        }
    state.approve(approval)
    return state, current


class ProviderFixture:
    """Documented test responses; this object does not represent real GitHub."""

    def __init__(self, reviews, *, wrong_repo=False, wrong_parent=False, lose_ack=False):
        self.reviews = reviews
        self.calls = []
        self.wrong_repo = wrong_repo
        self.wrong_parent = wrong_parent
        self.lose_ack = lose_ack

    def __call__(self, request):
        self.calls.append(request)
        url = str(request.url)
        for r in self.reviews:
            if request.method == "GET" and url == r.repository_url:
                return httpx.Response(
                    200,
                    json={
                        "id": 999 if self.wrong_repo else r.repo_id,
                        "node_id": r.repo_node_id,
                        "full_name": f"{r.owner}/{r.repo}",
                        "url": r.repository_url,
                    },
                )
            if request.method == "GET" and url == r.branch_ref_url:
                return httpx.Response(
                    200,
                    json={
                        "ref": "refs/heads/" + r.branch,
                        "object": {
                            "type": "commit",
                            "sha": "c" * 40 if self.wrong_parent else PARENT,
                        },
                    },
                )
            if request.method == "GET" and url == r.contents_at(PARENT):
                return httpx.Response(404, json={"message": "Not Found"})
            if request.method == "PUT" and url == r.contents_url:
                if self.lose_ack:
                    raise httpx.ReadTimeout("synthetic acknowledgement loss", request=request)
                projected = project_create("PUT", r.contents_url, request.content, r)
                return httpx.Response(
                    201,
                    json={"content": {"sha": projected.git_blob_sha1}, "commit": {"sha": COMMIT}},
                )
        raise AssertionError(f"fixture received an unexpected target: {request.method} {url}")

    @property
    def mutations(self):
        return [r for r in self.calls if r.method == "PUT"]


def captured_broker(state, current, fixture):
    broker = ProtectedBroker(state, current)
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(fixture), follow_redirects=False)
    return broker


def last_receipt(state):
    verified = state.verify_receipts()
    assert verified["ok"]
    assert SECRET not in state.receipts_path.read_text()
    return verified["rows"][-1]["row"]


def test_reviewed_creation_claims_actual_finite_authority_before_credential_release(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    provider = ProviderFixture([r])
    broker = captured_broker(state, current, provider)
    events = []
    original_claim = broker_module.claim_effect_at_edge
    original_headers = broker._headers

    def actual_claim(reference, request, **kwargs):
        result = original_claim(reference, request, **kwargs)
        events.append(("edge-claimed", reference))
        return result

    def headers(values, url, *, materialize):
        if materialize:
            assert events and events[0][0] == "edge-claimed"
            events.append(("credential-materialized", url))
        return original_headers(values, url, materialize=materialize)

    monkeypatch.setattr(broker_module, "claim_effect_at_edge", actual_claim)
    monkeypatch.setattr(broker, "_headers", headers)
    try:
        result = broker.handle(protected_message(r))
        assert result["ok"] and result["outcome"] == "AMBIGUOUS"
        assert [(q.method, str(q.url)) for q in provider.calls] == [
            ("GET", r.repository_url),
            ("GET", r.branch_ref_url),
            ("GET", r.contents_at(PARENT)),
            ("PUT", r.contents_url),
        ]
        assert all(q.headers["authorization"] == "Bearer " + SECRET for q in provider.calls)
        expected = project_create("PUT", r.contents_url, creation(r), r)
        assert provider.mutations[0].content == expected.body
        expected_effect = effect_identity(effect_descriptor(r, broker.effect_namespace))
        assert result["effect_id"] == expected_effect
        row = last_receipt(state)
        assert row["decision"] == "ALLOW" and row["execution_occurred"] is None
        assert row["credential_released"] is True and row["transport_completed"] is True
        assert row["kernel"]["reason_code"] == "OUTCOME_UNKNOWN"
        grant = broker.store.get_grant(row["grant_id"])
        assert grant.verify()
        assert grant.id != broker.grant.id
        assert grant.approved_effect_ids == [expected_effect]
        assert grant.budget.limit == 1 and grant.budget.remaining == 0
        effect = broker.store.get_effect(expected_effect)
        assert effect[-1]["state"] == "AMBIGUOUS"
        proof_row = next(
            item["row"]
            for item in state.verify_receipts()["rows"]
            if item["row"].get("stage") == "authorized"
        )
        assert proof_row["intent"]["action"]["parameters"]["body_sha256"] == expected.body_sha256
        assert proof_row["proof"]["extensions"]["effect"]["effect_id"] == expected_effect
        assert events[0][0] == "edge-claimed"
    finally:
        broker.close()


@pytest.mark.parametrize(
    "body_changes,url_change",
    [
        ({"content": base64.b64encode(b"unreviewed patch").decode()}, None),
        ({"branch": "main"}, None),
        ({"message": "unreviewed message"}, None),
        ({"sha": PARENT}, None),
        ({"author": {}}, None),
        ({"trace_id": "reset"}, None),
        ({}, "/contents/patches/other.patch"),
        ({}, "/issues"),
        ({}, ""),
    ],
)
def test_exact_signed_profile_blocks_changed_or_expanded_effect_before_credentials(
    tmp_path, monkeypatch, body_changes, url_change
):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    provider = ProviderFixture([r])
    broker = captured_broker(state, current, provider)
    msg = protected_message(r, body=base64.b64encode(creation(r, **body_changes)).decode())
    if url_change is not None:
        msg["url"] = r.repository_url + url_change
    try:
        assert not broker.handle(msg)["ok"]
        assert provider.calls == []
        row = last_receipt(state)
        assert row["decision"] == "DENY"
        assert row["credential_released"] is False and row["execution_occurred"] is False
    finally:
        broker.close()


@pytest.mark.parametrize("bad", ["repo", "parent"])
def test_failed_authenticated_preflight_reports_credential_release_but_no_creation(
    tmp_path, monkeypatch, bad
):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    provider = ProviderFixture([r], wrong_repo=bad == "repo", wrong_parent=bad == "parent")
    broker = captured_broker(state, current, provider)
    try:
        assert not broker.handle(protected_message(r))["ok"]
        assert provider.calls and provider.mutations == []
        assert all(q.headers["authorization"] == "Bearer " + SECRET for q in provider.calls)
        row = last_receipt(state)
        assert row["credential_released"] is True
        assert row["execution_occurred"] is False
        assert row["observation_stage"] == "preflight"
    finally:
        broker.close()


@pytest.mark.parametrize("lose_ack", [False, True])
def test_trace_session_and_broker_restart_cannot_reset_creation_ownership(
    tmp_path, monkeypatch, lose_ack
):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    provider = ProviderFixture([r], lose_ack=lose_ack)
    broker = captured_broker(state, current, provider)
    try:
        first = broker.handle(
            protected_message(r, headers={"X-Trace-ID": "first"}, session_id="one")
        )
        assert bool(first["ok"]) is (not lose_ack)
        first_row = last_receipt(state)
        assert first_row["outcome"] == "AMBIGUOUS"
        effect_id = first_row["effect_id"]
        assert len(provider.mutations) == 1
        assert not broker.handle(
            protected_message(r, headers={"X-Trace-ID": "second"}, session_id="two")
        )["ok"]
        assert len(provider.mutations) == 1
    finally:
        broker.close()
    restarted = captured_broker(state, discover(state.root, env={}), provider)
    try:
        assert not restarted.handle(
            protected_message(r, headers={"X-Trace-ID": "restart"}, session_id="three")
        )["ok"]
        assert len(provider.mutations) == 1
        assert restarted.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"
        row = last_receipt(state)
        assert row["credential_released"] is False and row["execution_occurred"] is False
    finally:
        restarted.close()


def test_separately_reviewed_second_path_remains_usable(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    first, second = reviewed(), reviewed("patches/second.patch")
    state, current = approved_project(tmp_path, [first, second])
    provider = ProviderFixture([first, second])
    broker = captured_broker(state, current, provider)
    try:
        a, b = broker.handle(protected_message(first)), broker.handle(protected_message(second))
        assert a["ok"] and b["ok"] and a["effect_id"] != b["effect_id"]
        assert len(provider.mutations) == 2
        assert last_receipt(state)["outcome"] == "AMBIGUOUS"
    finally:
        broker.close()


def test_model_grant_cannot_authorize_the_github_power(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r], with_model=True)
    broker = ProtectedBroker(state, current)
    try:
        grant = broker.store.get_grant(broker.grant.id)
        action = Action(
            grant_id=grant.id,
            type=capability(scan_power(r)),
            target=r.contents_url,
            params={},
            est_cost=1,
        )
        decision = broker.pdp.decide(grant, action)
        assert decision.outcome == DecisionOutcome.DENY
        assert broker.store.get_grant(grant.id).budget.remaining == grant.budget.remaining
    finally:
        broker.close()


def test_independent_kernel_refuses_changed_intent_before_any_http(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    provider = ProviderFixture([r])
    broker = captured_broker(state, current, provider)
    original = broker.effect_edge.protect

    def altered_intent(intent, proof, handler):
        value = copy.deepcopy(intent.to_dict())
        value["action"]["parameters"]["body_sha256"] = "f" * 64
        return original(ActionIntent.from_dict(value), proof, handler)

    monkeypatch.setattr(broker.effect_edge, "protect", altered_intent)
    try:
        assert not broker.handle(protected_message(r))["ok"]
        assert provider.calls == []
        row = last_receipt(state)
        assert row["decision"] == "DENY" and row["credential_released"] is False
        assert row["execution_occurred"] is False
        assert row["kernel"]["reason_code"]
    finally:
        broker.close()


def test_unsigned_profile_mutation_cannot_self_approve(tmp_path):
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    path = state.path / "approved.json"
    envelope = json.loads(path.read_text())
    envelope["payload"]["protected_github"][0]["review"]["path"] = "unreviewed.patch"
    path.write_text(json.dumps(envelope))
    with pytest.raises(AirlockError):
        ProtectedBroker(state, current)


@pytest.mark.parametrize("method,suffix", [("POST", "/issues"), ("DELETE", ""), ("POST", None)])
def test_unapproved_issue_delete_and_egress_expansions_do_not_reach_provider(
    tmp_path, monkeypatch, method, suffix
):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    provider = ProviderFixture([r])
    broker = captured_broker(state, current, provider)
    try:
        url = r.repository_url + suffix if suffix is not None else "https://egress.invalid/capture"
        msg = protected_message(r, method=method, url=url)
        assert not broker.handle(msg)["ok"]
        assert provider.calls == []
        row = last_receipt(state)
        assert row["decision"] == "DENY" and row["credential_released"] is False
        assert row["execution_occurred"] is False
    finally:
        broker.close()


def test_new_signed_profile_parent_does_not_reset_ambiguous_effect(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, current = approved_project(tmp_path, [r])
    provider = ProviderFixture([r])
    broker = captured_broker(state, current, provider)
    try:
        first = broker.handle(protected_message(r))
        assert first["ok"] and first["outcome"] == "AMBIGUOUS"
        original_effect = first["effect_id"]
    finally:
        broker.close()
    # Even a new host-signed approval must not clear the old owner's ambiguity.
    new_profile = signed_profile(r)
    new_profile["review"]["expected_parent_sha"] = "c" * 40
    state.approve({**current, "protected_github": [new_profile]})
    restarted = captured_broker(state, current, provider)
    try:
        assert not restarted.handle(protected_message(r))["ok"]
        assert len(provider.mutations) == 1
        assert restarted.store.get_effect(original_effect)[-1]["state"] == "AMBIGUOUS"
        assert last_receipt(state)["credential_released"] is False
    finally:
        restarted.close()


def test_source_authority_removal_disables_old_signed_github_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    r = reviewed()
    state, _ = approved_project(tmp_path, [r])
    (tmp_path / "agent.py").write_text("print('no GitHub authority remains')\n")
    current = discover(tmp_path, env={})
    provider = ProviderFixture([r])
    broker = captured_broker(state, current, provider)
    try:
        assert not broker.handle(protected_message(r))["ok"]
        assert provider.calls == []
        assert last_receipt(state)["credential_released"] is False
    finally:
        broker.close()
