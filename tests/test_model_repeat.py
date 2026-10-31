"""One logical model call owns inference, not one prompt; a consequence stays owned."""

import base64
import json
from types import SimpleNamespace

import httpx
import pytest
from test_github_protected_integration import (
    MODEL_URL,
    SECRET,
    ProviderFixture,
    approved_project,
    captured_broker,
    protected_message,
    reviewed,
)
from test_model_endpoints import ENDPOINT, message
from test_model_timeouts import configure

from actenon_airlock.evidence import load_public_key, verify_offline
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.workflow import status


def _completion(request, content="ok"):
    return httpx.Response(
        200,
        json={
            "model": "test-model",
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": content}}
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        },
    )


def _broker(state, provider):
    broker = ProtectedBroker(state, discover(state.root, env={}))
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    return broker


def _rows(state):
    return [item["row"] for item in state.verify_receipts()["rows"]]


def _lost(calls):
    def provider(request):
        calls.append(request)
        raise httpx.ReadTimeout("response lost", request=request)

    return provider


def _answered(calls):
    def provider(request):
        calls.append(request)
        return _completion(request, f"answer {len(calls)}")

    return provider


def _text(value):
    body = base64.b64decode(value["response"]["body"])
    return json.loads(body)["choices"][0]["message"]["content"]


def test_rerunning_a_project_can_send_the_same_first_prompt(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    for _ in range(2):
        broker = _broker(state, lambda request: calls.append(request) or _completion(request))
        try:
            assert broker.handle(message())["ok"]
        finally:
            broker.close()
    assert len(calls) == 2


def test_unresolved_inference_still_holds_within_its_run(tmp_path):
    state = configure(tmp_path, 600)
    calls = []

    def lost(request):
        calls.append(request)
        raise httpx.ReadTimeout("response lost", request=request)

    broker = _broker(state, lost)
    try:
        assert not broker.handle(message())["ok"]
        assert not broker.handle(message())["ok"]
    finally:
        broker.close()
    assert len(calls) == 1


def test_identical_requests_are_separate_calls_with_their_own_answers(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, _answered(calls))
    try:
        replies = [broker.handle(message()) for _ in range(3)]
    finally:
        broker.close()
    assert all(reply["ok"] for reply in replies)
    # Nothing is cached: each answer is the provider's own.
    assert [_text(reply) for reply in replies] == ["answer 1", "answer 2", "answer 3"]
    assert len(calls) == 3 and len({call.content for call in calls}) == 1
    assert len({reply["effect_id"] for reply in replies}) == 3
    answered = [r for r in _rows(state) if r.get("stage") == "response-received"]
    assert [r["inference_invocation"] for r in answered] == [1, 2, 3]
    assert not any(r["inference_retry"] for r in answered)
    assert len({r["inference_run"] for r in answered}) == 1
    assert status(state)["inference"] == {
        "dispatched": 3,
        "confirmed": 3,
        "unconfirmed": 0,
        "retries_held": 0,
    }


def test_each_repeat_is_bound_to_its_own_signed_proof(tmp_path):
    state = configure(tmp_path, 600)
    broker = _broker(state, _answered([]))
    try:
        broker.handle(message())
        broker.handle(message())
    finally:
        broker.close()
    proofs = [r for r in _rows(state) if r.get("stage") == "authorized"]
    assert [r["intent"]["action"]["parameters"]["inference_invocation"] for r in proofs] == [1, 2]
    assert len({r["proof_id"] for r in proofs}) == 2
    report = verify_offline(
        state.receipts_path.read_bytes(),
        load_public_key(str(state.path / "public-key.json")),
    )
    assert report["integrity"]["ok"]
    assert len(report["provider_truth"]["unresolved_ambiguous"]) == 0


def test_repeats_stop_at_the_call_budget_without_reaching_the_provider(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, _answered(calls))
    try:
        assert all(broker.handle(message())["ok"] for _ in range(128))
        over = broker.handle(message())
    finally:
        broker.close()
    assert not over["ok"] and over["reason"] == "grant status is exhausted"
    assert len(calls) == 128


@pytest.mark.parametrize("body", [{"model": "unapproved"}, {"max_tokens": 129}, {"tools": []}])
def test_a_repeat_gets_no_wider_model_authority(tmp_path, body):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, _answered(calls))
    try:
        assert broker.handle(message())["ok"]
        assert not broker.handle(message(**body))["ok"]
        assert not broker.handle(message(**body))["ok"]
    finally:
        broker.close()
    assert len(calls) == 1


def test_emergency_stop_refuses_a_repeat(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, _answered(calls))
    try:
        assert broker.handle(message())["ok"]
        state.set_emergency_stop("test")
        assert not broker.handle(message())["ok"]
    finally:
        broker.close()
    assert len(calls) == 1


def test_a_lost_reply_stays_unconfirmed_and_its_retry_is_not_dispatched(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, _lost(calls))
    try:
        first = broker.handle(message())
        retry = broker.handle(message())
    finally:
        broker.close()
    assert not first["ok"] and "unknown" in first["reason"]
    assert not retry["ok"]
    assert len(calls) == 1
    rows = _rows(state)
    held = next(r for r in rows if r["decision"] == "DENY")
    assert held["inference_retry"] is True and held["inference_invocation"] == 1
    # The hold carries no claim about what the provider did with the first call.
    assert held["execution_occurred"] is False and "outcome" not in held
    summary = status(state)
    assert summary["inference"] == {
        "dispatched": 1,
        "confirmed": 0,
        "unconfirmed": 1,
        "retries_held": 1,
    }
    assert len(summary["unresolved_effects"]) == 1


def test_a_held_retry_does_not_spend_the_call_budget(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, _lost(calls))
    try:
        broker.handle(message())
        before = broker.store.get_grant(broker.grant.id).budget.remaining
        assert not broker.handle(message())["ok"]
        assert broker.store.get_grant(broker.grant.id).budget.remaining == before
    finally:
        broker.close()


def test_a_lost_reply_does_not_stop_a_different_prompt(tmp_path):
    state = configure(tmp_path, 600)
    seen = []

    def provider(request):
        seen.append(request)
        if len(seen) == 1:
            raise httpx.ReadTimeout("response lost", request=request)
        return _completion(request)

    broker = _broker(state, provider)
    try:
        assert not broker.handle(message())["ok"]
        assert broker.handle(message(temperature=0.5))["ok"]
        assert not broker.handle(message())["ok"]
    finally:
        broker.close()
    assert len(seen) == 2


def test_a_repeat_that_loses_its_reply_is_held_on_its_own_call(tmp_path):
    state = configure(tmp_path, 600)
    calls = []

    def provider(request):
        calls.append(request)
        if len(calls) == 2:
            raise httpx.ReadTimeout("response lost", request=request)
        return _completion(request)

    broker = _broker(state, provider)
    try:
        assert broker.handle(message())["ok"]
        assert not broker.handle(message())["ok"]
        assert not broker.handle(message())["ok"]
    finally:
        broker.close()
    assert len(calls) == 2
    held = next(r for r in _rows(state) if r["decision"] == "DENY")
    assert held["inference_invocation"] == 2


@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(500, json={"error": "failed"}),
        httpx.Response(200, json={"model": "test-model"}),
        httpx.Response(200, text="not json"),
    ],
)
def test_an_answer_that_is_not_confirmed_still_holds_its_retry(tmp_path, reply):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, lambda request: calls.append(request) or reply)
    try:
        assert broker.handle(message())["outcome"] == "AMBIGUOUS"
        assert not broker.handle(message())["ok"]
    finally:
        broker.close()
    assert len(calls) == 1


def test_the_agent_cannot_name_or_reset_an_invocation(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    broker = _broker(state, _lost(calls))
    try:
        assert not broker.handle(message())["ok"]
        forged = {
            **message(),
            "inference_invocation": 99,
            "inference_run": "agent-chosen",
            "invocation": 99,
            "params": {"inference_invocation": 99},
        }
        assert not broker.handle(forged)["ok"]
        assert not broker.handle({**message(), "headers": {"x-stainless-retry-count": "0"}})["ok"]
        for header in ("idempotency-key", "x-airlock-invocation"):
            assert not broker.handle({**message(), "headers": {header: "fresh"}})["ok"]
        # A field in the model request is outside the signed request shape.
        assert not broker.handle(message(inference_invocation=99))["ok"]
    finally:
        broker.close()
    assert len(calls) == 1
    rows = [r for r in _rows(state) if "inference_invocation" in r]
    assert {r["inference_invocation"] for r in rows} == {1}


def test_model_identity_needs_the_supervisors_invocation(tmp_path):
    state = configure(tmp_path, 600)
    broker = _broker(state, _answered([]))
    parameters = {"method": "POST", "body_sha256": "a" * 64, "headers_effect_sha256": "b" * 64}
    intent = SimpleNamespace(
        action=SimpleNamespace(capability="cap", parameters=parameters),
        target=SimpleNamespace(resource_id=ENDPOINT, resource_type="http"),
    )
    try:
        with pytest.raises(KeyError):
            broker._http_effect_descriptor(intent)
        parameters["inference_invocation"] = 7
        key = broker._http_effect_descriptor(intent)["semantic_key"]
    finally:
        broker.close()
    assert key["invocation"] == 7 and key["run"] == broker.inference_run


def test_a_github_creation_stays_single_use_beside_repeated_inference(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    review = reviewed()
    state, current = approved_project(tmp_path, [review], with_model=True)
    github = ProviderFixture([review])
    inference = []

    def provider(request):
        if str(request.url) == MODEL_URL:
            inference.append(request)
            return _completion(request)
        return github(request)

    model = {**message(), "url": MODEL_URL}
    broker = captured_broker(state, current, provider)
    try:
        assert broker.handle(model)["ok"] and broker.handle(model)["ok"]
        assert broker.handle(protected_message(review))["ok"]
        assert broker.handle(model)["ok"]
        # Neither a repeat in this run nor a new run reopens the creation.
        assert not broker.handle(protected_message(review))["ok"]
    finally:
        broker.close()
    restarted = captured_broker(state, current, provider)
    try:
        assert not restarted.handle(protected_message(review))["ok"]
        effect_id = next(
            row["effect_id"] for row in _rows(state) if row.get("outcome") == "AMBIGUOUS"
        )
        owner = restarted.store.get_effect(effect_id)[-1]
    finally:
        restarted.close()
    assert len(inference) == 3
    assert len(github.mutations) == 1
    assert owner["state"] == "AMBIGUOUS"
    assert not set(owner["descriptor"]["semantic_key"]) & {"run", "invocation"}
    assert all(
        "inference_invocation" not in row for row in _rows(state) if "github" in row["action"]
    )
