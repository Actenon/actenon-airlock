"""Responses authority and ambiguity regressions, with provider-side observations."""

import base64
import copy
import json

import httpx
import pytest
from responses_fixture import ENDPOINT, MODEL, PRICES, ScriptedProvider, events, stream, text

from actenon_airlock import responses_inference as contract
from actenon_airlock.agents import parse_prices
from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import discover
from actenon_airlock.model_constraints import validate_profile
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State
from actenon_airlock.workflow import status

REQUEST = {
    "model": MODEL,
    "stream": True,
    "store": False,
    "input": [
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "Fix the bug"}],
        }
    ],
}
PROFILE = {
    "provider": "openai-responses",
    "contract": contract.CONTRACT,
    "models": [MODEL],
    "max_output_tokens": 16000,
    "max_input_bytes": 2 * 1024 * 1024,
    "price_microusd_per_mtok": parse_prices(PRICES),
    "max_run_microusd": 5_000_000,
    "anthropic_betas": [],
}
SECRET = "synthetic-host-only-openai-key"


def configure(root, budget="5"):
    assert (
        main(
            [
                "setup",
                "--path",
                str(root),
                "--agent",
                "codex-cli",
                "--model",
                MODEL,
                "--approve",
                "--max-run-usd",
                budget,
                "--price-per-mtok",
                PRICES,
            ]
        )
        == 0
    )
    return State(root)


def message(body=REQUEST, **changes):
    return {
        "kind": "protected-http",
        "method": "POST",
        "url": ENDPOINT,
        "headers": {"Content-Type": "application/json"},
        "body": base64.b64encode(json.dumps({**body, **changes}).encode()).decode(),
    }


@pytest.fixture
def broker(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path)
    provider = ScriptedProvider([[text("Done")]])
    broker = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    yield state, broker, provider
    broker.close()


def test_actual_dispatch_is_capped_canonical_authorized_and_credential_separated(broker):
    state, subject, provider = broker
    result = subject.handle(
        message(client_metadata={"session_id": "trace"}, prompt_cache_key="cache")
    )
    assert result["ok"] and result["outcome"] == "COMMITTED"
    sent = provider.requests[0]
    assert sent.headers["authorization"] == "Bearer " + SECRET
    assert json.loads(sent.content) == {**REQUEST, "max_output_tokens": 16000}
    assert SECRET not in state.receipts_path.read_text()
    assert status(state)["inference"]["confirmed"] == 1


@pytest.mark.parametrize(
    "change",
    [
        {"model": "other"},
        {"store": True},
        {"stream": 1},
        {"max_output_tokens": True},
        {"max_output_tokens": "100"},
        {"max_output_tokens": 16001},
        {"previous_response_id": "resp_old"},
        {"conversation": "prior"},
        {"background": True},
        {"service_tier": "priority"},
        {"tools": [{"type": "web_search"}]},
        {"tools": [{"type": "mcp", "server_url": "https://sink.invalid"}]},
        {"tools": [{"type": "function", "name": "external_mutation", "parameters": {}}]},
        {
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_image", "image_url": "https://sink.invalid"}],
                }
            ]
        },
        {"input": [{"type": "item_reference", "id": "prior"}]},
    ],
)
def test_unsupported_requests_never_reach_provider(broker, change):
    _, subject, provider = broker
    assert subject.handle(message(**change))["ok"] is False
    assert provider.requests == []


def test_duplicate_members_and_nonfinite_refused():
    for data in (b'{"model":"a","model":"b"}', b'{"x":NaN}'):
        with pytest.raises(AirlockError):
            contract.check_request(data, PROFILE)


def test_profile_requires_contract_and_typed_bounds():
    assert validate_profile(PROFILE) == PROFILE
    for field, value in (
        ("contract", "other"),
        ("max_input_bytes", True),
        ("max_run_microusd", 0),
        ("anthropic_betas", ["x"]),
    ):
        with pytest.raises(AirlockError):
            validate_profile({**PROFILE, field: value})
    missing = {
        k: v
        for k, v in PROFILE.items()
        if k
        not in {
            "contract",
            "max_input_bytes",
            "price_microusd_per_mtok",
            "max_run_microusd",
            "anthropic_betas",
        }
    }
    with pytest.raises(AirlockError):
        validate_profile(missing)


def test_trace_changes_cannot_reset_unconfirmed_inference(broker):
    state, subject, provider = broker
    calls = []

    def lost(request):
        calls.append(request)
        raise httpx.ReadTimeout("Acknowledgement lost", request=request)

    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(lost))
    for trace in ("first", "changed"):
        subject.handle(message(client_metadata={"session_id": trace}, prompt_cache_key=trace))
    assert len(calls) == 1
    assert len(status(state)["unresolved_effects"]) == 1


def test_complete_stream_usage_and_truncation():
    request = {**REQUEST, "max_output_tokens": 16000}
    body = stream([text("Done")])
    observed = contract.observe(200, body, request)
    assert observed.confirmed
    assert observed.usage == {
        "input_tokens": 90,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 10,
        "output_tokens": 20,
    }
    for damaged in (
        body[:-20],
        body.split(b"event: response.completed")[0],
        body.replace(b'"cached_tokens": 10', b'"cached_tokens": 101'),
        body.replace(b'"output_tokens": 20', b'"output_tokens": true'),
    ):
        assert not contract.observe(200, damaged, request).confirmed
    changed = copy.deepcopy(events([text("Done")]))
    changed[-1]["response"]["output"] = [text("different")]
    assert not contract.observe(
        200, "".join("data: " + json.dumps(e) + "\n\n" for e in changed).encode(), request
    ).confirmed


def test_confirmed_identical_requests_remain_separate_useful_calls(broker):
    state, subject, provider = broker
    provider.steps.append([text("Second useful answer")])
    assert subject.handle(message())["outcome"] == "COMMITTED"
    assert subject.handle(message())["outcome"] == "COMMITTED"
    assert len(provider.requests) == 2
    assert status(state)["inference"]["confirmed"] == 2


def test_explicit_rate_limit_can_retry_without_holding_false_success(broker):
    state, subject, provider = broker
    provider.steps.insert(0, httpx.Response(429, json={"error": {"code": "rate_limit_exceeded"}}))
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    assert subject.handle(message())["outcome"] == "COMMITTED"
    assert len(provider.requests) == 2
    assert status(state)["model_spend"]["declined_calls"] == 1


def test_partial_stream_does_not_establish_success_or_release_retry(broker):
    _, subject, provider = broker
    provider.steps[0] = httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        content=stream([text("unfinished")])[:-40],
    )
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    assert not subject.handle(message())["ok"]
    assert len(provider.requests) == 1
