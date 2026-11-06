"""Specification-derived wire cases, NOT captured GAUNTLET V3.2 responses.

Source: https://developers.openai.com/api/reference/resources/responses
The documented direct caller metadata is rejected by the original item allowlist.
"""

import copy
import json

import httpx
import pytest
from responses_fixture import ScriptedProvider, events, text, tool
from test_responses_inference import (  # noqa: F401
    PROFILE,
    REQUEST,
    SECRET,
    broker,
    configure,
    message,
)

from actenon_airlock import responses_inference as contract
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.workflow import status


def wire(items):
    return "".join(
        "event: " + e["type"] + "\ndata: " + json.dumps(e) + "\n\n" for e in items
    ).encode()


def output(kind="function_call", caller=True):
    value = tool("local", "python -m pytest -q")
    if kind == "custom_tool_call":
        value.update(type=kind, name="apply_patch", input="*** Begin Patch\n*** End Patch")
        del value["arguments"]
    if caller:
        value["caller"] = {"type": "direct"}
    return value


def observe(seq):
    return contract.observe(200, wire(seq), {**REQUEST, "max_output_tokens": 16000})


@pytest.mark.parametrize("kind", ["function_call", "custom_tool_call"])
@pytest.mark.parametrize("caller", [{"type": "direct"}, None])
def test_documented_direct_caller_confirms(kind, caller):
    value = {**output(kind), "caller": caller}
    result = observe(events([value]))
    assert result.confirmed
    assert result.usage["output_tokens"] == 20


def test_documented_caller_releases_reservation_for_continuation(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path, "0.7")
    provider = ScriptedProvider([[output()], [text("Continued")]])
    subject = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(provider))
    # A held first call plus the second reservation exceeds this signed budget.
    first = subject.handle(message())
    second = subject.handle(message(instructions="Continue"))
    assert first["outcome"] == "COMMITTED"
    assert second["outcome"] == "COMMITTED"
    assert len(provider.requests) == 2
    assert subject.inference_spent == 2 * 1055
    assert status(state)["integrity_ok"]
    subject.close()


@pytest.mark.parametrize(
    "values",
    [
        [text("done")],
        [output(caller=False)],
        [output(caller=False), {**tool("second", "pwd")}],
        [
            {
                "type": "reasoning",
                "id": "reason",
                "summary": [{"type": "summary_text", "text": "Check the tests."}],
                "encrypted_content": "synthetic-opaque-data",
            },
            output("custom_tool_call", False),
        ],
    ],
)
def test_supported_output_shapes(values):
    assert observe(events(values)).confirmed


def damaged(case):
    seq = copy.deepcopy(events([output(caller=False)]))
    terminal = seq[-1]["response"]
    if case == "no-terminal":
        seq.pop()
    elif case == "no-item-done":
        seq = [e for e in seq if e["type"] != "response.output_item.done"]
    elif case == "response-id":
        terminal["id"] = "other"
    elif case == "created-model":
        seq[0]["response"]["model"] = "other"
    elif case == "progress-id":
        seq.insert(
            1,
            {
                "type": "response.in_progress",
                "response": {**seq[0]["response"], "id": "other"},
                "sequence_number": 0,
            },
        )
    elif case == "index":
        seq[-2]["output_index"] = 1
    elif case == "delta-id":
        seq[2]["item_id"] = "other"
    elif case == "delta-value":
        seq[2]["delta"] = "contradiction"
    elif case == "delta-type":
        seq[2]["delta"] = 7
    elif case == "done-value":
        seq[3]["arguments"] = "{}"
    elif case == "unknown-event":
        seq[2]["type"] = "response.unreviewed"
    elif case == "unknown-field":
        seq[2]["unreviewed"] = True
    elif case == "duplicate-terminal":
        seq.append(copy.deepcopy(seq[-1]))
    elif case == "duplicate-item":
        seq.insert(-1, copy.deepcopy(seq[-2]))
    elif case == "sequence":
        seq[2]["sequence_number"] = 0
    elif case == "terminal-output":
        terminal["output"] = [text("different")]
    elif case == "terminal-model":
        terminal["model"] = "unapproved"
    elif case == "incomplete":
        terminal.update(status="incomplete", incomplete_details={"reason": "max_output_tokens"})
        seq[-1]["type"] = "response.incomplete"
    elif case == "terminal-status":
        terminal["status"] = "in_progress"
    elif case == "missing-usage":
        terminal.pop("usage")
    elif case == "total":
        terminal["usage"]["total_tokens"] = 0
    elif case == "negative":
        terminal["usage"]["input_tokens"] = -1
    elif case == "boolean":
        terminal["usage"]["output_tokens"] = True
    elif case == "fraction":
        terminal["usage"]["output_tokens"] = 1.5
    elif case == "over-cap":
        terminal["usage"]["output_tokens"] = 16001
    elif case == "cache":
        terminal["usage"]["input_tokens_details"]["cached_tokens"] = 101
    elif case == "hosted-tool":
        terminal["output"][0]["type"] = "web_search_call"
    elif case == "program-caller":
        terminal["output"][0]["caller"] = {"type": "program", "caller_id": "program"}
    elif case == "malformed-arguments":
        for e in seq:
            if "item" in e and e["type"].endswith("done"):
                e["item"]["arguments"] = "not-json"
        seq[2]["delta"] = seq[3]["arguments"] = "not-json"
    else:
        raise AssertionError(case)
    return seq


CASES = [
    "no-terminal",
    "no-item-done",
    "response-id",
    "created-model",
    "progress-id",
    "index",
    "delta-id",
    "delta-value",
    "delta-type",
    "done-value",
    "unknown-event",
    "unknown-field",
    "duplicate-terminal",
    "duplicate-item",
    "sequence",
    "terminal-output",
    "terminal-model",
    "incomplete",
    "terminal-status",
    "missing-usage",
    "total",
    "negative",
    "boolean",
    "fraction",
    "over-cap",
    "cache",
    "hosted-tool",
    "program-caller",
    "malformed-arguments",
]


@pytest.mark.parametrize("case", CASES)
def test_invalid_or_uncertain_stream_holds(case, broker):  # noqa: F811
    seq = damaged(case)
    result = observe(seq)
    assert not result.confirmed and result.usage is None
    state, subject, provider = broker
    provider.steps = [httpx.Response(200, content=wire(seq))]
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    reserved = contract.reservation(
        len(provider.requests[0].content), 16000, PROFILE["price_microusd_per_mtok"]
    )
    assert subject.inference_spent == reserved
    assert not subject.handle(message())["ok"]
    assert len(provider.requests) == 1
    assert status(state)["integrity_ok"]


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b.rstrip(b"\n"),
        lambda b: b + b"data: {",
        lambda b: b.replace(b"event: response.created", b"event: response.failed"),
        lambda b: b.replace(b"data: ", b"junk: hidden\ndata: ", 1),
        lambda b: b.replace(b'"sequence_number": 0', b'"sequence_number": NaN'),
    ],
)
def test_malformed_framing_is_unconfirmed(change):
    assert not contract.observe(
        200, change(wire(events([text("done")]))), {**REQUEST, "max_output_tokens": 16000}
    ).confirmed


def resequence(seq):
    return [{**event, "sequence_number": i} for i, event in enumerate(seq)]


def test_interleaved_items_use_output_indices_not_completion_arrival_order():
    seq = events([output(), {**tool("second", "pwd"), "caller": {"type": "direct"}}])
    first_done = seq.pop(4)
    seq.insert(-1, first_done)
    assert observe(resequence(seq)).confirmed


@pytest.mark.parametrize(
    "case",
    [
        "no-added",
        "no-input-events",
        "unknown-response-field",
        "initial-input",
        "duplicate-call-id",
        "usage-details",
        "response-hosted-tools",
        "caller-extra",
        "input-over-bound",
    ],
)
def test_additional_contradictions_hold(case):
    seq = copy.deepcopy(events([output()]))
    response = seq[-1]["response"]
    if case == "no-added":
        seq.pop(1)
    elif case == "no-input-events":
        seq = [e for e in seq if "function_call_arguments" not in e["type"]]
    elif case == "unknown-response-field":
        response["unreviewed_extension"] = True
    elif case == "initial-input":
        seq[1]["item"]["arguments"] = "ignored-initial-input"
    elif case == "duplicate-call-id":
        seq = events([output(), {**output(), "id": "second"}])
    elif case == "usage-details":
        response["usage"]["output_tokens_details"] = {"reasoning_tokens": 21}
    elif case == "response-hosted-tools":
        response["tools"] = [{"type": "web_search"}]
    elif case == "caller-extra":
        response["output"][0]["caller"]["secret_extension"] = "untrusted"
    elif case == "input-over-bound":
        response["usage"].update(input_tokens=999999, total_tokens=1000019)
    result = observe(resequence(seq))
    assert not result.confirmed and result.usage is None


def test_diagnostics_keep_only_structural_metadata_and_hashes(broker):  # noqa: F811
    state, subject, provider = broker
    secret = "synthetic-sensitive-response-value"
    value = {**output(), "id": secret, "call_id": secret, "arguments": json.dumps({"cmd": secret})}
    seq = events([value], response_id=secret)
    provider.steps = [httpx.Response(200, content=wire(seq))]
    assert subject.handle(message())["outcome"] == "COMMITTED"
    row = [
        r
        for r in [json.loads(line) for line in state.receipts_path.read_text().splitlines()]
        if r.get("stage") == "response-received"
    ][0]
    diag = row["inference_observation"]
    assert secret not in json.dumps(diag)
    assert diag["event_count"] == len(seq)
    assert diag["terminal_status"] == "completed"
    assert diag["rejection_reason"] is None
    assert diag["validated_usage"] == row["inference_usage"]
    assert row["inference_reserved_microusd"] > row["inference_cost_microusd"] == 1055
    assert diag["events"][1]["item_type"] == "function_call"
    assert diag["events"][1]["sequence_number"] == 1
    assert len(diag["events"][1]["item_id_sha256"]) == 64


def test_rejection_reason_is_precise_and_content_free():
    result = observe(damaged("delta-id"))
    assert result.diagnostics["rejection_reason"] == "event-item-id"
    assert result.diagnostics["checked_sequence_number"] == 2
    seq = events([output()])
    seq[2]["type"] = "untrusted-event-name-containing-a-secret"
    result = observe(seq)
    assert result.diagnostics["rejection_reason"] == "unsupported-event-type"
    assert "untrusted-event-name" not in json.dumps(result.diagnostics)


def test_diagnostics_are_bounded_without_discarding_validation():
    seq = events([text("x" * 300)])
    delta = seq[3]
    seq[3:4] = [{**delta, "delta": "x"} for _ in range(300)]
    result = observe(resequence(seq))
    assert result.confirmed
    assert len(result.diagnostics["events"]) == 256
    assert result.diagnostics["events_truncated"]
    assert result.diagnostics["event_count"] == len(seq)
    seq[-1]["response"]["usage"]["output_tokens"] = -1
    assert not observe(resequence(seq)).confirmed


def test_failure_after_dispatch_before_observation_retains_reservation(broker, monkeypatch):  # noqa: F811
    state, subject, provider = broker

    def crash(*args):
        raise RuntimeError("synthetic interruption before observation")

    monkeypatch.setattr(contract, "observe", crash)
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    assert len(provider.requests) == 1
    assert subject.inference_spent == contract.reservation(
        len(provider.requests[0].content), 16000, PROFILE["price_microusd_per_mtok"]
    )
    assert not subject.handle(message())["ok"]
    assert len(provider.requests) == 1
    assert status(state)["integrity_ok"]


def test_caller_extension_does_not_expand_outbound_history():
    from actenon_airlock.common import AirlockError

    with pytest.raises(AirlockError, match="local tool call fields"):
        contract.check_request(json.dumps({**REQUEST, "input": [output()]}).encode(), PROFILE)


def test_diagnostics_are_covered_by_receipt_signature(broker):  # noqa: F811
    state, subject, provider = broker
    assert subject.handle(message())["outcome"] == "COMMITTED"
    rows = [json.loads(line) for line in state.receipts_path.read_text().splitlines()]
    assert state.verify_receipts()["ok"]
    rows[-1]["inference_observation"]["rejection_reason"] = "forged"
    state.receipts_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert not state.verify_receipts()["ok"]
    from actenon_airlock.common import AirlockError

    with pytest.raises(AirlockError, match="Receipt journal is invalid"):
        subject.handle(message())
    assert len(provider.requests) == 1


def test_reasoning_content_stream_and_transport_padding():
    value = {
        "type": "reasoning",
        "id": "reasoning-content",
        "summary": [{"type": "summary_text", "text": "synthetic reasoning"}],
    }
    seq = events([value])
    for event in seq:
        event["type"] = (
            event["type"]
            .replace("reasoning_summary_part", "content_part")
            .replace("reasoning_summary_text", "reasoning_text")
        )
        if "summary_index" in event:
            event["content_index"] = event.pop("summary_index")
        if "part" in event:
            event["part"]["type"] = "reasoning_text"
        if "item" in event:
            current = event["item"]
            current["content"] = current.pop("summary")
            current["summary"] = []
            for part in current["content"]:
                part["type"] = "reasoning_text"
        if event["type"].endswith("delta"):
            event["obfuscation"] = "synthetic-padding-must-not-be-logged"
    body = (b": keepalive\n\n" + wire(seq)).replace(b"\n", b"\r\n")
    result = contract.observe(200, body, {**REQUEST, "max_output_tokens": 16000})
    assert result.confirmed
    assert "synthetic reasoning" not in json.dumps(result.diagnostics)
    assert "synthetic-padding" not in json.dumps(result.diagnostics)
