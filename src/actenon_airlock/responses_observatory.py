"""Bounded read-only diagnostics; never a completion, authority or price oracle.

Only the authoritative observer settles inference. Probes below deliberately
isolate substructures to collect independent failures, so a successful probe
does NOT establish a valid response. Nothing from this module enters dispatch,
replay, budget calculation or the authoritative observer's input.
"""

from __future__ import annotations

import io
import json

from actenon.core.json import loads_no_duplicate_keys

from . import responses_inference as contract
from .common import AirlockError

MAX_BYTES = 4 * 1024 * 1024
# Patch-writing turns stream about one delta per output token, so a valid
# response can far exceed the 42-68 events seen in live first turns. Frames
# up to MAX_EVENTS are inspected in order; later frames are skipped lexically
# except lifecycle snapshots, which carry the terminal metadata and usage.
MAX_EVENTS = 4096
MAX_LATE_LIFECYCLE = 4
MAX_LINES = 65536
MAX_DEPTH = 24
MAX_NODES = 8192  # per JSON document (one SSE frame, a JSON body or the request)
MAX_TOTAL_NODES = 131072  # cumulative across all parsed frames
MAX_ISSUES = 32
MAX_PATH = 10
MAX_FIELDS = 4
MAX_PROBES = 512
MAX_REPORT_BYTES = 16384

_LIFECYCLE = {
    "response.created",
    "response.in_progress",
    "response.completed",
    "response.incomplete",
}
_LIFECYCLE_FIELDS = {
    "object",
    "id",
    "model",
    "status",
    "output",
    "usage",
    "error",
    "incomplete_details",
}
_USAGE_FIELDS = {
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "input_tokens_details",
    "output_tokens_details",
}


class _Limit(Exception):
    pass


class _Inspection:
    def __init__(self, request):
        self.request = request
        self.issues = []
        self.truncated = False
        # Some frames were never inspected (skipped after a cap, oversized, or
        # past a scan limit). Conclusions that need the whole sequence are then
        # disclosed as not inspected instead of being reported as defects.
        self.incomplete = False
        self.events = 0
        self.skipped = 0
        self.nodes = 0
        self.probes = 0
        self.strictness = {}
        self.policies = set()
        self.metadata = {}
        self.identity = None

    def issue(self, stage, reason, path=(), fields=None, detail=None):
        # All stage/reason/path strings are literals or trusted validator codes.
        # No provider value or provider-selected path component is copied here.
        if len(path) > MAX_PATH or (fields and len(fields) > MAX_FIELDS):
            self.truncated = True
        record = {"stage": stage, "reason": reason, "path": list(path[:MAX_PATH])}
        if fields:
            record["fields"] = fields[:MAX_FIELDS]
        if detail:
            record["detail"] = detail
        if record not in self.issues:
            if len(self.issues) >= MAX_ISSUES:
                self.truncated = True
                return
            self.issues.append(record)

    def unknown(self, value, allowed, stage, path, catalogue=None):
        if isinstance(value, dict) and set(value) - allowed:
            fields = contract._unexpected_fields(set(value) - allowed, catalogue or allowed)
            self.issue(stage, "unexpected-fields", path, fields["unexpected_fields"])
            if fields["unexpected_field_count"] > MAX_FIELDS:
                self.truncated = True

    def probe(self, stage, path, fn, *args, **kwargs):
        if self.probes >= MAX_PROBES:
            self.truncated = True
            self.issue("inspection", "inspection-limit")
            return
        self.probes += 1
        try:
            fn(*args, **kwargs)
        except contract._Rejected as exc:
            # _Rejected carries only fixed reason codes. Never copy str() of
            # parser, SDK, provider or arbitrary exceptions into a receipt.
            self.issue(
                stage,
                str(exc),
                path,
                exc.diagnostic.get("unexpected_fields"),
                exc.diagnostic.get("tool_rejection_reason"),
            )
        except (AirlockError, ValueError, TypeError, KeyError, AttributeError, IndexError):
            self.issue(stage, "structure-invalid", path)

    def response(self, response, path):
        self.probe("response-object", path, contract._response_schema, response)
        if not isinstance(response, dict):
            return
        base = {"object": "response", "model": self.request["model"]}
        # Isolated field probes cannot be hidden by a preceding unknown field,
        # malformed image policy, or a conflicting tool definition.
        for field in sorted(contract._RESPONSE_FIELDS - {"tools", "image", "tool_usage"}):
            if field in response or field in {"object", "model"}:
                self.probe(
                    "response-metadata",
                    (*path, field),
                    contract._response,
                    {**base, field: response.get(field)},
                    self.request,
                )
        if "image" in response:
            self.probe(
                "response-image",
                (*path, "image"),
                contract._image_metadata,
                response["image"],
                self.policies,
            )
        if "tool_usage" in response:
            self.hosted(response["tool_usage"], (*path, "tool_usage"))
        if "tools" in response:
            self.tools(response["tools"], self.request.get("tools", []), (*path, "tools"))
        identifier = response.get("id")
        if not contract._identifier(identifier):
            self.issue("response-identity", "response-id", (*path, "id"))
        elif self.identity is None:
            self.identity = identifier
        elif identifier != self.identity:
            self.issue("response-identity", "response-id-mismatch", (*path, "id"))
        for field in sorted(
            contract._RESPONSE_FIELDS
            - _LIFECYCLE_FIELDS
            - {"tools", "image", "completed_at", "tool_usage"}
        ):
            if field not in response:
                continue  # Absence is not an assertion of a different default.
            value = response[field]
            if field in {"presence_penalty", "frequency_penalty"} and value is None:
                value = 0
            encoded = contract.canonical(value)
            if field in self.metadata and encoded != self.metadata[field]:
                self.issue("response-metadata", "metadata-changed", (*path, field))
            self.metadata[field] = encoded
        output = response.get("output")
        if not isinstance(output, list):
            self.issue("output", "response-output-schema", (*path, "output"))
        else:
            for index, value in enumerate(output):
                self.probe("output", (*path, "output", index), contract._output, value)
        if response.get("status") in {"completed", "incomplete", "failed"}:
            self.usage(response.get("usage"), (*path, "usage"))

    def tools(self, echoed, approved, path, depth=0):
        self.probe(
            "tool-echo",
            path,
            contract._response_tools,
            echoed,
            approved,
            strictness=self.strictness if depth == 0 else None,
        )
        if not isinstance(echoed, list) or not isinstance(approved, list) or depth > 1:
            return
        by_name = {t.get("name"): t for t in approved if isinstance(t, dict)}
        for index, tool in enumerate(echoed):
            location = (*path, index)
            self.probe("tool-echo", location, contract._echo_tool, tool, (index,))
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                continue
            other = by_name.get(tool["name"])
            if other is None:
                self.issue("tool-echo", "response-tools", location, detail="identity")
            else:
                self.probe("tool-echo", location, contract._response_tools, [tool], [other])
                if tool.get("type") == "namespace":
                    self.tools(
                        tool.get("tools"), other.get("tools"), (*location, "tools"), depth + 1
                    )

    def hosted(self, value, path):
        self.probe("hosted-usage", path, contract._tool_usage, value)
        # Independently examine both accounting categories and nested counts,
        # even if the first category/shape already failed its semantic probe.
        shapes = {
            (): {"image_gen", "web_search"},
            ("web_search",): {"num_requests"},
            ("image_gen",): {
                "input_tokens",
                "output_tokens",
                "total_tokens",
                "cached_tokens",
                "input_tokens_details",
                "output_tokens_details",
                "cached_tokens_details",
            },
            ("image_gen", "input_tokens_details"): {"image_tokens", "text_tokens"},
            ("image_gen", "output_tokens_details"): {"image_tokens", "text_tokens"},
            ("image_gen", "cached_tokens_details"): {"cached_image_tokens", "cached_text_tokens"},
        }
        for suffix, allowed in shapes.items():
            node = value
            for key in suffix:
                node = node.get(key) if isinstance(node, dict) else None
            if not isinstance(node, dict):
                continue
            self.unknown(
                node, allowed, "hosted-usage", (*path, *suffix), contract._PUBLIC_TOOL_USAGE_FIELDS
            )
            for key in sorted(allowed & set(node)):
                if key not in {
                    "image_gen",
                    "web_search",
                    "input_tokens_details",
                    "output_tokens_details",
                    "cached_tokens_details",
                }:
                    self.probe(
                        "hosted-usage",
                        (*path, *suffix, key),
                        contract._zero_tool_count,
                        node[key],
                        "tool_usage",
                    )

    def usage(self, value, path):
        # A diagnostic-only fixture isolates token validation from unrelated
        # rejected metadata. Its result is discarded and cannot settle anything.
        fixture = {
            "object": "response",
            "id": "diagnostic",
            "model": self.request["model"],
            "status": "completed",
            "output": [],
            "usage": value,
        }
        self.probe("usage", path, contract._usage, fixture, self.request)
        self.unknown(value, _USAGE_FIELDS, "usage", path)
        if not isinstance(value, dict):
            return
        for name, allowed in (
            ("input_tokens_details", {"cached_tokens", "cache_write_tokens"}),
            ("output_tokens_details", {"reasoning_tokens"}),
        ):
            self.unknown(value.get(name), allowed, "usage", (*path, name))
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            if not contract._count(value.get(name)):
                self.issue("usage", "usage-count", (*path, name))

    def stream(self, events, gaps=frozenset()):
        previous = None
        terminal = False
        projected = []
        for index, event in enumerate(events):
            path = ("events", index)
            kind = event.get("type")
            if not isinstance(kind, str) or kind not in contract._EVENTS:
                self.issue("event", "unsupported-event-type", path)
                continue
            if index == 0 and kind != "response.created" and 0 not in gaps:
                self.issue("event", "stream-created-missing", path)
            number = event.get("sequence_number")
            # Continuity cannot be judged across frames that were not inspected.
            if index in gaps:
                previous = None
            if not contract._count(number) or (previous is not None and number != previous + 1):
                self.issue("event", "event-sequence", path)
            previous = number if contract._count(number) else None
            if terminal:
                self.issue("event", "event-after-terminal", path)
            if kind in _LIFECYCLE:
                response = event.get("response")
                self.response(response, (*path, "response"))
                terminal |= kind == "response.completed"
                # Isolate stream/output consistency from metadata checks. This
                # copy stays diagnostic-only and is never passed to observe().
                event = (
                    {
                        **event,
                        "response": {
                            key: value
                            for key, value in response.items()
                            if key in _LIFECYCLE_FIELDS
                        },
                    }
                    if isinstance(response, dict)
                    else event
                )
            elif kind in {"response.output_item.added", "response.output_item.done"}:
                self.probe(
                    "output",
                    (*path, "item"),
                    contract._output,
                    event.get("item"),
                    partial=kind.endswith("added"),
                )
            projected.append(event)
        if not terminal:
            # A terminal event may lie in frames that were never inspected.
            self.issue(
                "completion", "terminal-not-inspected" if self.incomplete else "terminal-missing"
            )
        if self.incomplete:
            # Delta/done and item consistency need every frame; do not guess.
            self.issue("inspection", "stream-integrity-not-inspected")
            return
        trace = contract._Trace(b"")
        for event in projected:
            trace.record(event)
        self.probe(
            "stream-integrity", (), contract._stream_response, projected, self.request, trace
        )

    def report(self):
        result = {
            "schema": "actenon-airlock/responses-contract-observatory/v1",
            "authoritative": False,
            "issues": self.issues,
            "truncated": self.truncated,
            "events_inspected": self.events,
            "events_skipped": self.skipped,
            "probes": self.probes,
            "limits": {
                "bytes": MAX_BYTES,
                "events": MAX_EVENTS,
                "late_lifecycle_events": MAX_LATE_LIFECYCLE,
                "lines": MAX_LINES,
                "depth": MAX_DEPTH,
                "structural_tokens": MAX_NODES,
                "total_structural_tokens": MAX_TOTAL_NODES,
                "issues": MAX_ISSUES,
                "path": MAX_PATH,
                "fields_per_issue": MAX_FIELDS,
                "report_bytes": MAX_REPORT_BYTES,
                "probes": MAX_PROBES,
            },
        }
        while len(json.dumps(result).encode()) > MAX_REPORT_BYTES:
            result["issues"].pop()
            result["truncated"] = True
        return result


def _guard(body):
    # Scan before JSON allocation: byte bound, nesting and structural token
    # budget cap parse memory, recursive comparisons and all subsequent walks.
    if len(body) > MAX_BYTES:
        raise _Limit
    depth = nodes = 0
    quoted = escaped = False
    for byte in body:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            nodes += 1
        elif byte in (125, 93):
            depth = max(0, depth - 1)
        elif byte in (44, 58):
            nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise _Limit
    return nodes


def _parse(data, inspection=None):
    nodes = _guard(data.encode() if isinstance(data, str) else data)
    if inspection is not None:
        # Cumulative budget: per-frame guards alone would allow many frames.
        inspection.nodes += nodes
        if inspection.nodes > MAX_TOTAL_NODES:
            raise _Limit
    value = loads_no_duplicate_keys(data)
    json.dumps(value, allow_nan=False)
    return value


def _frames(body, inspection):
    # Returns retained frames and the indices that follow uninspected frames.
    # Retention is at most MAX_EVENTS + MAX_LATE_LIFECYCLE frames; all other
    # work is a single bounded line scan over at most MAX_BYTES.
    frames, gaps = [], set()
    data, name = [], None
    late = 0
    stopped = False

    def skip():
        inspection.skipped += 1
        inspection.incomplete = inspection.truncated = True
        gaps.add(len(frames))

    def finish():
        nonlocal late, stopped
        position = ("events", len(frames))
        capped = len(frames) - late >= MAX_EVENTS
        if capped:
            inspection.issue("parse", "inspection-limit")
            # After the cap only named lifecycle snapshots are parsed. Their
            # metadata and usage are the evidence a failed response most needs.
            if name not in _LIFECYCLE or late >= MAX_LATE_LIFECYCLE:
                skip()
                return
        try:
            value = _parse("\n".join(data), inspection)
            if not isinstance(value, dict):
                raise ValueError
        except _Limit:
            inspection.issue("parse", "inspection-limit", position)
            if inspection.nodes > MAX_TOTAL_NODES:
                stopped = True
            skip()
            return
        except (ValueError, TypeError):
            inspection.issue("parse", "malformed-response", position)
            skip()
            return
        if name is not None and name != value.get("type"):
            inspection.issue("parse", "sse-event-name-mismatch", position)
        late += capped
        frames.append(value)

    for index, line in enumerate(io.StringIO(body.decode("utf-8"))):
        if index >= MAX_LINES or stopped:
            inspection.issue("parse", "inspection-limit")
            inspection.incomplete = inspection.truncated = True
            data, name = [], None  # An unfinished frame here is not a defect.
            break
        line = line.rstrip("\r\n")
        if not line:
            if data or name is not None:
                finish()
            data, name = [], None
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        elif line.startswith("event:"):
            name = line[6:].strip()
        elif not line.startswith(":"):
            inspection.issue("parse", "sse-unsupported-field", ("events", len(frames)))
    if data or name is not None:
        inspection.issue("parse", "sse-partial-frame")
    inspection.events = len(frames)
    return frames, frozenset(gaps)


def inspect_response(status, body, request):
    inspection = _Inspection(request)
    try:
        if len(body) > MAX_BYTES:
            raise _Limit
        # The approved request also bounds comparisons against private schemas.
        _guard(contract.canonical(request))
        if status != 200:
            inspection.issue("transport", "http-status")
        elif request["stream"]:
            inspection.stream(*_frames(body, inspection))
        else:
            response = _parse(body)
            inspection.response(response, ("response",))
            if not isinstance(response, dict) or response.get("status") != "completed":
                inspection.issue("completion", "terminal-missing")
    except _Limit:
        inspection.truncated = True
        inspection.issue("parse", "inspection-limit")
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
        inspection.issue("parse", "malformed-response")
    return inspection.report()
