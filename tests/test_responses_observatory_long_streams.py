"""Realistically long streams: diagnostics must neither invent nor lose defects.

Live GPT-5.5 first turns produced 42-68 events, but patch-writing turns stream
roughly one delta event per output token. A diagnostic that truncates such a
valid stream must not claim a missing terminal event, and a defect in the
terminal snapshot must still be reported. None of this affects authority: the
authoritative observer alone decides confirmation.
"""

import copy
import json

import pytest
from responses_full_fixture import EIGHT, full_response
from test_responses_inference import PROFILE, REQUEST
from test_responses_observation import wire
from test_responses_tool_echo import observe

from actenon_airlock import responses_inference as contract
from actenon_airlock import responses_observatory as diagnostic


def _replace(value, old, new):
    if isinstance(value, dict):
        return {k: _replace(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace(v, old, new) for v in value]
    return new if value == old else value


def long_stream(deltas):
    """The full documented fixture with its text split into many valid deltas."""
    seq = full_response()
    index = next(i for i, e in enumerate(seq) if e["type"] == "response.output_text.delta")
    seq = _replace(seq, seq[index]["delta"], "y" * deltas)
    seq[index : index + 1] = [dict(copy.deepcopy(seq[index]), delta="y") for _ in range(deltas)]
    for number, event in enumerate(seq):
        event["sequence_number"] = number
    return seq


def approved():
    request = {**REQUEST, "tools": EIGHT, "max_output_tokens": 16000, "stream": True}
    return json.loads(contract.check_request(json.dumps(request).encode(), PROFILE))


def reasons(report):
    return {issue["reason"] for issue in report["issues"]}


@pytest.mark.parametrize("deltas", [300, 1200, 3000])
def test_long_valid_stream_has_no_false_diagnostics(deltas):
    result = observe(EIGHT, long_stream(deltas))
    assert result.confirmed
    report = result.diagnostics["contract_observatory"]
    assert report["issues"] == []
    assert not report["truncated"]
    assert report["events_inspected"] == deltas + 8


def test_terminal_snapshot_beyond_event_cap_is_still_inspected():
    seq = long_stream(diagnostic.MAX_EVENTS + 500)
    final = seq[-1]["response"]
    final["image"] = {"context_compression": "auto"}
    final["usage"]["total_tokens"] = 0
    final["synthetic-secret-name"] = "synthetic-secret-value"
    result = observe(EIGHT, seq)
    assert not result.confirmed and result.usage is None
    report = result.diagnostics["contract_observatory"]
    assert {"response-image-policy", "usage-total", "response-schema"} <= reasons(report)
    assert "terminal-missing" not in reasons(report)
    assert report["truncated"] and report["events_skipped"] > 0
    assert "synthetic-secret" not in json.dumps(result.diagnostics)


def test_uninspected_tail_is_disclosed_not_reported_missing(monkeypatch):
    monkeypatch.setattr(diagnostic, "MAX_LINES", 50)
    report = diagnostic.inspect_response(200, wire(long_stream(300)), approved())
    assert report["truncated"]
    assert "terminal-missing" not in reasons(report)
    assert "terminal-not-inspected" in reasons(report)


def test_genuinely_missing_terminal_in_long_stream_is_still_reported():
    seq = long_stream(1200)
    seq.pop()
    report = diagnostic.inspect_response(200, wire(seq), approved())
    assert "terminal-missing" in reasons(report)
    assert "terminal-not-inspected" not in reasons(report)


def test_oversized_frame_does_not_hide_independent_terminal_defects():
    seq = long_stream(10)
    bad = {"type": "response.output_text.delta", "sequence_number": 0}
    bad["synthetic-secret"] = json.loads("[" * 40 + "0" + "]" * 40)
    seq.insert(5, bad)
    for number, event in enumerate(seq):
        event["sequence_number"] = number
    seq[-1]["response"]["tool_usage"]["web_search"]["num_requests"] = 1
    result = observe(EIGHT, seq)
    assert not result.confirmed
    report = result.diagnostics["contract_observatory"]
    assert "inspection-limit" in reasons(report)
    assert "response-hosted-tool-usage" in reasons(report)
    assert "terminal-missing" not in reasons(report)
    assert "synthetic-secret" not in json.dumps(result.diagnostics)


def test_maximum_size_delta_stream_is_bounded():
    # Unnamed-frame and named-frame floods near the 4 MiB authoritative bound.
    frame = b'event: response.output_text.delta\ndata: {"type":"response.output_text.delta"}\n\n'
    body = frame * ((diagnostic.MAX_BYTES - 1) // len(frame))
    report = diagnostic.inspect_response(200, body, approved())
    assert report["truncated"]
    assert len(json.dumps(report).encode()) <= diagnostic.MAX_REPORT_BYTES
    assert report["events_inspected"] <= diagnostic.MAX_EVENTS + diagnostic.MAX_LATE_LIFECYCLE
