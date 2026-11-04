"""Independent SDK 2.54.0/documentation-derived cases, never captured live bodies.

The three Optional response fields may be absent/null. Their populated forms
describe features outside the signed no-conversation GPT-5.5 request contract.
"""

import copy
import itertools
import json
from pathlib import Path

import httpx
import pytest
from responses_fixture import ScriptedProvider, events, text
from test_responses_inference import (  # noqa: F401
    PROFILE,
    REQUEST,
    SECRET,
    broker,
    configure,
    message,
)
from test_responses_observation import wire

from actenon_airlock import responses_inference as contract
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.workflow import status

FIELDS = ("conversation", "moderation", "prompt_cache_options")
NULL_SHAPES = [dict.fromkeys(s) for n in range(4) for s in itertools.combinations(FIELDS, n)]
MODERATION_RESULT = {
    "type": "moderation_result",
    "model": "omni-moderation-latest",
    "flagged": False,
    "categories": {"violence": False},
    "category_scores": {"violence": 0.001},
    "category_applied_input_types": {"violence": ["text"]},
}
# Valid provider schema values are not necessarily supported contract values.
POPULATED = {
    "conversation": {"id": "conv_synthetic"},
    "moderation": {"input": MODERATION_RESULT, "output": MODERATION_RESULT},
    "prompt_cache_options": {"mode": "implicit", "ttl": "30m"},
}


def sequence(metadata):
    seq = copy.deepcopy(events([text("Synthetic completion")]))
    documented = json.loads((Path(__file__).parent / "fixtures/response-metadata.json").read_text())
    for event in seq:
        if "response" in event:
            event["response"].update(documented)
            event["response"].update(copy.deepcopy(metadata))
    return seq


def observed(seq, stream=True):
    body = wire(seq) if stream else json.dumps(seq[-1]["response"]).encode()
    return contract.observe(200, body, {**REQUEST, "stream": stream, "max_output_tokens": 16000})


@pytest.mark.parametrize("metadata", NULL_SHAPES)
@pytest.mark.parametrize("stream", [True, False])
def test_documented_absent_null_combinations_confirm(metadata, stream):
    result = observed(sequence(metadata), stream)
    assert result.confirmed
    assert result.usage == {
        "input_tokens": 90,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 10,
        "output_tokens": 20,
    }


@pytest.mark.parametrize("metadata", NULL_SHAPES)
def test_existing_valid_metadata_with_nullable_extensions(metadata):
    assert observed(
        sequence(
            {**metadata, "prompt_cache_retention": "24h", "metadata": {}, "created_at": 1793740800}
        )
    ).confirmed


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("position", [0, -1])
def test_absent_and_null_are_semantically_equivalent(field, position):
    seq = sequence({})
    seq[position]["response"][field] = None
    assert observed(seq).confirmed


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", [False, 0, "", [], {}, "private-reference", {"unexpected": None}])
@pytest.mark.parametrize("position", [0, -1])
def test_invalid_or_unsupported_values_remain_unconfirmed(field, value, position):
    seq = sequence(dict.fromkeys(FIELDS))
    seq[position]["response"][field] = value
    result = observed(seq)
    assert not result.confirmed and result.usage is None


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("position", [0, -1, "both"])
def test_documented_populated_features_and_contradictions_are_unsupported(field, position):
    seq = sequence(dict.fromkeys(FIELDS))
    for index in [0, -1] if position == "both" else [position]:
        seq[index]["response"][field] = copy.deepcopy(POPULATED[field])
    assert not observed(seq).confirmed
    if position != 0:
        assert not observed(seq, stream=False).confirmed


def test_moderation_error_and_explicit_cache_mode_are_unsupported():
    error = {"type": "error", "code": "synthetic", "message": "private-value"}
    for metadata in (
        {"moderation": {"input": error, "output": error}},
        {"prompt_cache_options": {"mode": "explicit", "ttl": "30m"}},
    ):
        assert not observed(sequence(metadata)).confirmed


@pytest.mark.parametrize("metadata", NULL_SHAPES)
@pytest.mark.parametrize("failure", ["incomplete", "partial", "bad-usage", "bad-output", "unknown"])
def test_metadata_never_substitutes_for_completion_validation(metadata, failure):
    seq = sequence(metadata)
    if failure == "incomplete":
        seq[-1]["type"] = "response.incomplete"
        seq[-1]["response"].update(
            status="incomplete", incomplete_details={"reason": "max_output_tokens"}
        )
    elif failure == "partial":
        seq.pop()
    elif failure == "bad-usage":
        seq[-1]["response"]["usage"]["total_tokens"] = 0
    elif failure == "bad-output":
        seq[-1]["response"]["output"] = []
    else:
        seq[0]["response"]["unknown-extension"] = None
    result = observed(seq)
    assert not result.confirmed and result.usage is None


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("populated", [False, True])
def test_response_metadata_does_not_expand_outbound_authority(broker, field, populated):  # noqa: F811
    _, subject, provider = broker
    value = POPULATED[field] if populated else None
    with pytest.raises(AirlockError):
        contract.check_request(json.dumps({**REQUEST, field: value}).encode(), PROFILE)
    assert not subject.handle(message(**{field: value}))["ok"]
    assert provider.requests == []


@pytest.mark.parametrize("metadata", NULL_SHAPES[1:])
def test_completed_metadata_settles_and_allows_budgeted_continuation(
    tmp_path, monkeypatch, metadata
):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path, "0.7")
    provider = ScriptedProvider(
        [httpx.Response(200, content=wire(sequence(metadata))), [text("Continue")]]
    )
    subject = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(provider))
    try:
        assert subject.handle(message())["outcome"] == "COMMITTED"
        assert subject.inference_spent == 1055
        assert subject.handle(message(instructions="Continue"))["outcome"] == "COMMITTED"
        assert subject.inference_spent == 2110
        assert len(provider.requests) == 2
        assert status(state)["integrity_ok"]
        assert json.loads(provider.requests[0].content) == {**REQUEST, "max_output_tokens": 16000}
    finally:
        subject.close()


@pytest.mark.parametrize(
    "metadata", [POPULATED, *[{f: v} for f, v in POPULATED.items()], {"private-unknown": "secret"}]
)
def test_unsupported_metadata_holds_reservation_and_blocks_replay(broker, metadata):  # noqa: F811
    state, subject, provider = broker
    provider.steps = [httpx.Response(200, content=wire(sequence(metadata)))]
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    assert subject.inference_spent == 501335
    for trace in ("first", "changed"):
        assert not subject.handle(
            message(client_metadata={"session_id": trace}, prompt_cache_key=trace)
        )["ok"]
    assert len(provider.requests) == 1
    assert status(state)["integrity_ok"]


@pytest.mark.parametrize("stream", [True, False])
def test_structural_diagnostic_is_bounded_and_never_copies_unknown_names_or_values(stream):
    secret = "synthetic-secret-in-property-name-and-value"
    metadata = {secret + str(i): secret for i in range(40)}
    metadata["prompt_cache_diagnostics"] = {"secret": secret}
    result = observed(sequence(metadata), stream)
    diag = result.diagnostics
    assert not result.confirmed
    assert diag["rejection_reason"] == "response-schema"
    assert diag["validation_stage"] == "response-object"
    assert diag["unexpected_field_count"] == 41
    assert diag["unexpected_fields_truncated"] is True
    assert len(diag["unexpected_fields"]) == 16
    assert "prompt_cache_diagnostics" in diag["unexpected_fields"]
    assert all(
        n == "prompt_cache_diagnostics" or (n.startswith("sha256:") and len(n) == 71)
        for n in diag["unexpected_fields"]
    )
    assert secret not in json.dumps(diag)
    assert len(json.dumps({k: v for k, v in diag.items() if k.startswith("unexpected")})) < 1500


@pytest.mark.parametrize("field", FIELDS)
def test_metadata_rejection_names_only_public_field(field):
    result = observed(sequence({field: {"secret-name": "secret-value"}}))
    assert result.diagnostics["validation_stage"] == "response-metadata"
    assert result.diagnostics["rejected_field"] == field
    assert "secret" not in json.dumps(result.diagnostics)


def test_schema_diagnostic_is_signed_and_console_is_content_free(broker, capsys):  # noqa: F811
    state, subject, provider = broker
    secret = "synthetic-arbitrary-name-and-value-secret"
    provider.steps = [httpx.Response(200, content=wire(sequence({secret: secret})))]
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    receipt_text = state.receipts_path.read_text()
    console = capsys.readouterr()
    assert secret not in receipt_text + console.out + console.err
    assert state.verify_receipts()["ok"]
    rows = [json.loads(line) for line in receipt_text.splitlines()]
    row = next(r for r in rows if r.get("inference_observation"))
    assert row["inference_observation"]["validation_stage"] == "response-object"
    row["inference_observation"]["unexpected_fields"] = ["forged"]
    state.receipts_path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert not state.verify_receipts()["ok"]


@pytest.mark.parametrize("metadata", NULL_SHAPES)
@pytest.mark.parametrize("stream", [True, False])
def test_documented_zero_cache_writes_confirms_with_complete_sdk_shape(metadata, stream):
    from openai.types.responses.response import Response

    seq = sequence(metadata)
    usage = seq[-1]["response"]["usage"]
    usage["input_tokens_details"]["cache_write_tokens"] = 0
    usage["output_tokens_details"] = {"reasoning_tokens": 0}
    # Only a fixture sanity check: SDK acceptance never drives production policy.
    for event in seq:
        if "response" in event:
            Response.model_validate(event["response"])
    result = observed(seq, stream)
    assert result.confirmed
    assert result.usage["cache_creation_input_tokens"] == 0


@pytest.mark.parametrize("value", [None, False, True, -1, 1, 101, 0.0, "0", {}, []])
def test_unpriced_or_malformed_cache_writes_retain_the_reservation(broker, value):  # noqa: F811
    state, subject, provider = broker
    seq = sequence(dict.fromkeys(FIELDS))
    seq[-1]["response"]["usage"]["input_tokens_details"]["cache_write_tokens"] = value
    provider.steps = [httpx.Response(200, content=wire(seq))]
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    assert subject.inference_spent == 501335
    assert not subject.handle(message())["ok"]
    assert len(provider.requests) == 1
    assert status(state)["integrity_ok"]
