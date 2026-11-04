"""V4.1 names, independently authored values: no captured response bodies.

Tool-usage shapes follow the official Responses reference, including required
families/core counts and optional image cache/output details. Penalty semantics
are documented for Chat Completions; their live Responses values remain unknown.
"""

import copy
import hashlib
import itertools
import json
from pathlib import Path

import httpx
import pytest
from responses_fixture import ScriptedProvider
from test_response_schema_compatibility import observed, sequence
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

ZERO_TOOLS = json.loads(
    (Path(__file__).parent / "fixtures/response-zero-tool-usage.json").read_text()
)
PENALTIES = ("presence_penalty", "frequency_penalty")
OPTIONAL = ("cached_tokens", "cached_tokens_details", "output_tokens_details")
TOOL_SHAPES = []
for length in range(4):
    for omitted in itertools.combinations(OPTIONAL, length):
        shape = copy.deepcopy(ZERO_TOOLS)
        for field in omitted:
            del shape["image_gen"][field]
        TOOL_SHAPES.append(shape)
VALID = [
    {},
    *[{f: v} for f in PENALTIES for v in (None, 0, 0.0, -0.0)],
    *[{"tool_usage": shape} for shape in TOOL_SHAPES],
    *[
        {"presence_penalty": a, "frequency_penalty": b, "tool_usage": shape}
        for a, b, shape in itertools.product((None, 0, 0.0), (None, 0, -0.0), TOOL_SHAPES)
    ],
]
ALL_ZERO = {"presence_penalty": 0, "frequency_penalty": 0.0, "tool_usage": ZERO_TOOLS}


def lifecycle(metadata):
    seq = sequence(metadata)
    progress = copy.deepcopy(seq[0])
    progress["type"] = "response.in_progress"
    seq.insert(1, progress)
    for n, event in enumerate(seq):
        event["sequence_number"] = n
    return seq


def altered(path, value, *, remove=False):
    shape = copy.deepcopy(ZERO_TOOLS)
    obj = shape
    for part in path[:-1]:
        obj = obj[part]
    if remove:
        del obj[path[-1]]
    else:
        obj[path[-1]] = value
    return shape


LEAVES = [
    ("web_search", "num_requests"),
    ("image_gen", "input_tokens"),
    ("image_gen", "output_tokens"),
    ("image_gen", "total_tokens"),
    ("image_gen", "cached_tokens"),
    ("image_gen", "input_tokens_details", "image_tokens"),
    ("image_gen", "input_tokens_details", "text_tokens"),
    ("image_gen", "output_tokens_details", "image_tokens"),
    ("image_gen", "output_tokens_details", "text_tokens"),
    ("image_gen", "cached_tokens_details", "cached_image_tokens"),
    ("image_gen", "cached_tokens_details", "cached_text_tokens"),
]
OBJECTS = [
    (),
    ("web_search",),
    ("image_gen",),
    ("image_gen", "input_tokens_details"),
    ("image_gen", "output_tokens_details"),
    ("image_gen", "cached_tokens_details"),
]


@pytest.mark.parametrize("metadata", VALID)
@pytest.mark.parametrize("stream", [True, False])
def test_zero_default_metadata_confirms_only_validated_usage(metadata, stream):
    result = observed(lifecycle(metadata), stream)
    assert result.confirmed
    assert result.usage == {
        "input_tokens": 90,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 10,
        "output_tokens": 20,
    }


@pytest.mark.parametrize("field", PENALTIES)
@pytest.mark.parametrize(
    "value",
    [False, True, "0", [], {}, -2, 2, -0.01, 0.01, 3, float("nan"), float("inf"), -float("inf")],
)
@pytest.mark.parametrize("position", [0, 1, -1])
def test_unsupported_penalty_at_any_snapshot_is_unconfirmed(field, value, position):
    seq = lifecycle(ALL_ZERO)
    seq[position]["response"][field] = value
    result = observed(seq)
    assert not result.confirmed and result.usage is None
    if position == -1:
        assert not observed(seq, False).confirmed


@pytest.mark.parametrize("path", LEAVES)
@pytest.mark.parametrize(
    "value", [1, -1, False, True, 0.0, None, "0", {}, [], float("nan"), float("inf")]
)
def test_hosted_tool_counters_are_exact_integer_zero(path, value):
    result = observed(lifecycle({"tool_usage": altered(path, value)}))
    assert not result.confirmed and result.usage is None
    assert not observed(lifecycle({"tool_usage": altered(path, value)}), False).confirmed


@pytest.mark.parametrize("path", OBJECTS)
@pytest.mark.parametrize("value", [None, {}, [], False, 0, "private-value"])
def test_malformed_or_empty_tool_objects_are_not_documented_zero_usage(path, value):
    shape = altered(path, value) if path else value
    result = observed(lifecycle({"tool_usage": shape}))
    assert not result.confirmed and result.usage is None


@pytest.mark.parametrize("path", [*LEAVES, *(p for p in OBJECTS if p)])
def test_only_documented_optional_tool_properties_may_be_omitted(path):
    optional = len(path) == 2 and path[0] == "image_gen" and path[1] in OPTIONAL
    result = observed(lifecycle({"tool_usage": altered(path, None, remove=True)}))
    assert result.confirmed is optional
    if not optional:
        assert result.usage is None


@pytest.mark.parametrize("position", [0, 1, -1])
@pytest.mark.parametrize("path", [("web_search", "num_requests"), ("image_gen", "input_tokens")])
def test_hosted_usage_cannot_be_erased_by_later_zero_metadata(position, path):
    seq = lifecycle(ALL_ZERO)
    seq[position]["response"]["tool_usage"] = altered(path, 1)
    result = observed(seq)
    assert not result.confirmed and result.usage is None
    assert result.diagnostics["rejection_reason"] == "response-hosted-tool-usage"
    assert result.diagnostics["validation_stage"] == "response-tool-usage"
    assert result.diagnostics["rejected_field"] == "tool_usage." + ".".join(path)


def test_equivalent_zero_absent_and_optional_detail_transitions():
    seq = lifecycle({})
    seq[1]["response"].update(
        {"presence_penalty": None, "frequency_penalty": -0.0, "tool_usage": TOOL_SHAPES[-1]}
    )
    seq[-1]["response"].update(ALL_ZERO)
    assert observed(seq).confirmed


@pytest.mark.parametrize(
    "failure",
    [
        "partial",
        "incomplete",
        "model",
        "identity",
        "output",
        "usage",
        "hosted-output",
        "hosted-tools",
        "unknown",
    ],
)
def test_zero_metadata_does_not_replace_existing_validation(failure):
    seq = lifecycle(ALL_ZERO)
    final = seq[-1]["response"]
    if failure == "partial":
        seq.pop()
    elif failure == "incomplete":
        seq[-1]["type"] = "response.incomplete"
        final.update(status="incomplete", incomplete_details={"reason": "max_output_tokens"})
    elif failure == "model":
        final["model"] = "different-model"
    elif failure == "identity":
        final["id"] = "different-response"
    elif failure == "output":
        final["output"] = []
    elif failure == "usage":
        final["usage"]["total_tokens"] = 0
    elif failure == "hosted-output":
        final["output"] = [{"type": "web_search_call", "id": "ws_test", "status": "completed"}]
    elif failure == "hosted-tools":
        final["tools"] = [{"type": "web_search"}]
    else:
        final["unreviewed-field"] = None
    result = observed(seq)
    assert not result.confirmed and result.usage is None


@pytest.mark.parametrize("field", [*PENALTIES, "tool_usage"])
def test_response_fields_cannot_expand_the_outbound_contract(broker, field):  # noqa: F811
    _, subject, provider = broker
    with pytest.raises(AirlockError):
        contract.check_request(json.dumps({**REQUEST, field: ALL_ZERO[field]}).encode(), PROFILE)
    assert not subject.handle(message(**{field: ALL_ZERO[field]}))["ok"]
    assert not provider.requests


@pytest.mark.parametrize("metadata", [{f: ALL_ZERO[f]} for f in ALL_ZERO] + [ALL_ZERO])
def test_valid_metadata_releases_hold_and_allows_budgeted_continuation(
    tmp_path, monkeypatch, metadata
):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path, "0.7")
    provider = ScriptedProvider([httpx.Response(200, content=wire(lifecycle(metadata)))] * 2)
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
    "failure", ["web", "image", "penalty", "malformed", "partial", "incomplete"]
)
def test_unsupported_or_incomplete_outcomes_hold_budget_and_replay_ownership(
    tmp_path, monkeypatch, failure
):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path, "0.7")
    seq = lifecycle(ALL_ZERO)
    if failure in ("web", "image"):
        path = (
            ("web_search", "num_requests") if failure == "web" else ("image_gen", "output_tokens")
        )
        seq[-1]["response"]["tool_usage"] = altered(path, 1)
    elif failure == "penalty":
        seq[1]["response"]["presence_penalty"] = 0.5
    elif failure == "malformed":
        seq[0]["response"]["tool_usage"] = {}
    elif failure == "partial":
        seq.pop()
    else:
        seq[-1]["type"] = "response.incomplete"
        seq[-1]["response"].update(status="incomplete")
    provider = ScriptedProvider([httpx.Response(200, content=wire(seq))])
    subject = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(provider))
    try:
        assert subject.handle(message())["outcome"] == "AMBIGUOUS"
        assert subject.inference_spent == 501335
        for trace in ("original", "changed"):
            assert not subject.handle(
                message(client_metadata={"session_id": trace}, prompt_cache_key=trace)
            )["ok"]
        assert not subject.handle(message(instructions="Continue"))["ok"]
        assert subject.inference_spent == 501335
        assert len(provider.requests) == 1
        assert status(state)["integrity_ok"]
    finally:
        subject.close()


@pytest.mark.parametrize("path", OBJECTS)
def test_nested_structural_diagnostics_are_bounded_and_signed(broker, capsys, path):  # noqa: F811
    state, subject, provider = broker
    secret = "synthetic-private-name-and-value"
    shape = copy.deepcopy(ZERO_TOOLS)
    obj = shape
    for part in path:
        obj = obj[part]
    obj.update({secret + str(i): secret for i in range(40)})
    provider.steps = [httpx.Response(200, content=wire(lifecycle({"tool_usage": shape})))]
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    receipts = state.receipts_path.read_text()
    console = capsys.readouterr()
    assert secret not in receipts + console.out + console.err
    assert state.verify_receipts()["ok"]
    rows = [json.loads(line) for line in receipts.splitlines()]
    row = next(r for r in rows if r.get("inference_observation"))
    diag = row["inference_observation"]
    assert diag["validation_stage"] == "response-tool-usage"
    assert diag["rejected_field"] == ".".join(("tool_usage", *path))
    assert diag["unexpected_field_count"] == 40
    assert diag["unexpected_fields_truncated"] is True
    assert len(diag["unexpected_fields"]) == 16
    assert all(n.startswith("sha256:") and len(n) == 71 for n in diag["unexpected_fields"])
    diag["rejected_field"] = "forged"
    state.receipts_path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert not state.verify_receipts()["ok"]


def test_live_name_hashes_and_pinned_sdk_gap():
    from openai.types.responses.response import Response

    expected = {
        "presence_penalty": "08cddebc8497c80ff162929c9a3dc3878a7cd855802eb092864dfa536182a419",
        "frequency_penalty": "6d0b2264042111e0d5f4058f083e1c4ef190cd3003657fa8015115ab2855be27",
        "tool_usage": "bedfbed57f7a6b61ee0de6808fb49c1a366eb7543f47f950bdb55a8411b5c9e2",
    }
    for name, digest in expected.items():
        assert (
            hashlib.sha256(json.dumps(name, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
            == digest
        )
        assert name not in Response.model_fields  # SDK 2.54.0, not an acceptance source.
