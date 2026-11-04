import copy
import json

import httpx
import pytest
from responses_fixture import ScriptedProvider
from responses_full_fixture import EIGHT, full_response
from test_responses_inference import PROFILE, REQUEST, SECRET, configure, message
from test_responses_observation import wire
from test_responses_tool_echo import observe

from actenon_airlock import responses_inference as contract
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker


@pytest.mark.parametrize("policy", ["enabled", "disabled"])
@pytest.mark.parametrize("streaming", [True, False])
def test_full_documented_supported_response_confirms(policy, streaming):
    result = observe(EIGHT, full_response(policy), streaming)
    assert result.confirmed, result.diagnostics
    assert result.usage == {
        "input_tokens": 90,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 10,
        "output_tokens": 20,
    }


@pytest.mark.parametrize("position", [0, 1, -1, "all"])
def test_image_omission_is_no_echo_and_does_not_choose_a_policy(position):
    seq = full_response()
    for index in (0, 1, -1) if position == "all" else (position,):
        del seq[index]["response"]["image"]
    assert observe(EIGHT, seq).confirmed


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        [],
        False,
        0,
        "enabled",
        {"context_compression": "auto"},
        {"context_compression": None},
        {"context_compression": []},
        {"context_compression": True},
        {"context_compression": "other"},
        {"context_compression": "enabled", "unknown-secret": "secret"},
    ],
)
@pytest.mark.parametrize("position", [0, 1, -1])
def test_unsupported_image_values_remain_unconfirmed(value, position):
    seq = full_response()
    seq[position]["response"]["image"] = value
    result = observe(EIGHT, seq)
    assert not result.confirmed and result.usage is None
    if position == -1:
        assert not observe(EIGHT, seq, False).confirmed


@pytest.mark.parametrize("position", [1, -1])
def test_conflicting_effective_policy_is_never_confirmed(position):
    seq = full_response()
    seq[position]["response"]["image"]["context_compression"] = "disabled"
    assert not observe(EIGHT, seq).confirmed


@pytest.mark.parametrize(
    "field,value",
    [
        ("store", True),
        ("background", True),
        ("conversation", {"id": "private"}),
        ("previous_response_id", "private"),
        ("access_programs", {}),
        ("moderation", {}),
        ("prompt_cache_options", {}),
        ("prompt_cache_diagnostics", {"type": "cache_hit"}),
        ("presence_penalty", 0.1),
        ("model", "other"),
        ("max_output_tokens", 100),
        ("tools", [{"type": "image_generation"}]),
        ("unexpected-billing", {"cost": 0}),
    ],
)
def test_full_contract_one_authority_sensitive_change_is_unconfirmed(field, value):
    seq = full_response()
    seq[-1]["response"][field] = value
    assert not observe(EIGHT, seq).confirmed


@pytest.mark.parametrize(
    "case",
    [
        "partial",
        "incomplete",
        "usage",
        "cache-write",
        "hosted",
        "output",
        "identity",
        "tool-schema",
    ],
)
def test_valid_image_metadata_cannot_replace_complete_contract_validation(case):
    seq = full_response()
    final = seq[-1]["response"]
    if case == "partial":
        seq.pop()
    elif case == "incomplete":
        seq[-1]["type"] = "response.incomplete"
        final["status"] = "incomplete"
    elif case == "usage":
        final["usage"] = None
    elif case == "cache-write":
        final["usage"]["input_tokens_details"]["cache_write_tokens"] = 1
    elif case == "hosted":
        final["tool_usage"]["image_gen"]["output_tokens"] = 1
    elif case == "output":
        final["output"] = [{"type": "image_generation_call", "id": "img"}]
    elif case == "identity":
        final["id"] = "other"
    else:
        final["tools"][0]["parameters"] = {}
    assert not observe(EIGHT, seq).confirmed


@pytest.mark.parametrize(
    "value", [{"context_compression": "enabled"}, {"context_compression": "disabled"}, None]
)
def test_response_image_metadata_does_not_enable_image_request_authority(value):
    with pytest.raises(AirlockError):
        contract.check_request(json.dumps({**REQUEST, "image": value}).encode(), PROFILE)
    request = copy.deepcopy(REQUEST)
    request["input"][0]["content"] = [
        {"type": "input_image", "image_url": "https://private.invalid"}
    ]
    with pytest.raises(AirlockError):
        contract.check_request(json.dumps(request).encode(), PROFILE)


@pytest.mark.parametrize("policy", ["enabled", "disabled"])
def test_full_broker_settlement_and_continuation(tmp_path, monkeypatch, policy):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path, "0.7")
    provider = ScriptedProvider([httpx.Response(200, content=wire(full_response(policy)))] * 2)
    subject = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(provider))
    try:
        assert subject.handle(message(tools=EIGHT))["outcome"] == "COMMITTED"
        assert subject.inference_spent == 1055
        assert (
            subject.handle(message(tools=EIGHT, instructions="Continue"))["outcome"] == "COMMITTED"
        )
        assert subject.inference_spent == 2110
        assert len(provider.requests) == 2 and state.verify_receipts()["ok"]
        assert "image" not in json.loads(provider.requests[0].content)
    finally:
        subject.close()
