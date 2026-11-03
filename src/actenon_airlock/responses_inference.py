"""Reviewed Responses transport for unchanged Codex; model tools confer no authority.

Only inline text/history and named client-side tools are supported. The supervisor
adds an omitted output cap BEFORE Permit hashes the exact dispatch bytes. This API
contract does not support the ChatGPT-plan preview, which rejects that cap.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from actenon.core.json import loads_no_duplicate_keys

from .agent_inference import MAX_INPUT_BYTES, PRICES, Observation, cost
from .common import AirlockError, canonical

CONTRACT = "openai-responses-agent/v1"
LOCAL_TOOLS = frozenset(
    {
        "get_goal",
        "create_goal",
        "update_goal",
        "exec_command",
        "write_stdin",
        "apply_patch",
        "update_plan",
        "view_image",
        "request_user_input",
        "request_user_input_async",
    }
)
REQUEST_FIELDS = frozenset(
    {
        "model",
        "stream",
        "input",
        "instructions",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "include",
        "prompt_cache_key",
        "text",
        "client_metadata",
        "max_output_tokens",
    }
)


def obj(value, fields, label):
    if not isinstance(value, dict) or set(value) - set(fields):
        raise AirlockError(f"Unsupported {label} fields")
    return value


def string(value, label):
    if not isinstance(value, str):
        raise AirlockError(f"{label} must be text")


def validate_profile(profile):
    if profile.get("contract") != CONTRACT or profile.get("provider") != "openai-responses":
        raise AirlockError("Unsupported Responses contract")
    for field, maximum, minimum in (
        ("max_input_bytes", MAX_INPUT_BYTES, 1),
        ("max_output_tokens", 64000, 16),
    ):
        value = profile.get(field)
        if type(value) is not int or not minimum <= value <= maximum:
            raise AirlockError(f"Invalid Responses {field}")
    if profile.get("anthropic_betas", []) != []:
        raise AirlockError("Responses does not accept Anthropic features")
    prices = profile.get("price_microusd_per_mtok")
    if (
        not isinstance(prices, dict)
        or set(prices) != set(PRICES)
        or any(type(v) is not int or v < 0 for v in prices.values())
    ):
        raise AirlockError("Responses needs reviewed prices for every token class")
    if prices["cache_write"] != 0:
        raise AirlockError("Responses has no separately priced cache-write class")
    if type(profile.get("max_run_microusd")) is not int or profile["max_run_microusd"] < 1:
        raise AirlockError("Responses needs a positive run spend bound")


def tools(items, *, nested=False):
    if not isinstance(items, list):
        raise AirlockError("Tools must be a list")
    for item in items:
        if not isinstance(item, dict):
            raise AirlockError("Tool must be an object")
        kind = item.get("type")
        if kind == "namespace" and not nested:
            obj(item, {"type", "name", "description", "tools"}, "namespace")
            if item.get("name") != "functions":
                raise AirlockError("Unreviewed tool namespace")
            tools(item.get("tools"), nested=True)
            continue
        if kind not in {"function", "custom"} or item.get("name") not in LOCAL_TOOLS:
            raise AirlockError("Provider-hosted or unreviewed tools are forbidden")
        obj(
            item,
            {"type", "name", "description", "parameters", "strict"}
            if kind == "function"
            else {"type", "name", "description", "format"},
            "local tool",
        )
        string(item.get("description", ""), "Tool description")
        if kind == "function":
            if (
                not isinstance(item.get("parameters"), dict)
                or type(item.get("strict", False)) is not bool
            ):
                raise AirlockError("Invalid local function schema")
        elif "format" in item:
            fmt = obj(item["format"], {"type", "syntax", "definition"}, "custom tool format")
            if fmt.get("type") != "grammar" or fmt.get("syntax") != "lark":
                raise AirlockError("Unsupported custom tool format")
            string(fmt.get("definition"), "Grammar")


def content(items):
    if isinstance(items, str):
        return
    if not isinstance(items, list):
        raise AirlockError("Inline text content is required")
    for part in items:
        obj(part, {"type", "text", "annotations", "logprobs"}, "text content")
        if part.get("type") not in {"input_text", "output_text", "summary_text", "reasoning_text"}:
            raise AirlockError("Fetched files, images and remote content are unsupported")
        string(part.get("text"), "Content")
        if part.get("annotations", []) != [] or part.get("logprobs", []) != []:
            raise AirlockError("Unsupported text annotations")


def item(value, *, output=False):
    if not isinstance(value, dict):
        raise AirlockError("History item must be an object")
    kind = value.get("type")
    common = {"type", "id", "status"}
    if kind == "additional_tools" and not output:
        obj(value, common | {"role", "tools"}, "tool declarations")
        if value.get("role") != "developer":
            raise AirlockError("Tool declaration role must be developer")
        tools(value.get("tools"))
    elif kind == "message":
        obj(value, common | {"role", "content", "phase"}, "message")
        if value.get("role") not in (
            {"assistant"} if output else {"system", "developer", "user", "assistant"}
        ):
            raise AirlockError("Unsupported message role")
        if value.get("phase") not in {None, "commentary", "final_answer"}:
            raise AirlockError("Unsupported message phase")
        content(value.get("content"))
    elif kind == "reasoning":
        obj(value, common | {"summary", "content", "encrypted_content"}, "reasoning")
        content(value.get("summary", []))
        if value.get("content") is not None:
            content(value["content"])
        if value.get("encrypted_content") is not None:
            string(value["encrypted_content"], "Encrypted reasoning")
    elif kind in {"function_call", "custom_tool_call"}:
        field = "arguments" if kind == "function_call" else "input"
        obj(
            value,
            common | {"call_id", "name", "namespace", field} | ({"caller"} if output else set()),
            "local tool call",
        )
        # Documented response-only metadata. Programmatic execution is not this contract.
        if output and value.get("caller") not in (None, {"type": "direct"}):
            raise AirlockError("Unsupported local tool caller")
        if value.get("name") not in LOCAL_TOOLS or value.get("namespace") not in {
            None,
            "functions",
        }:
            raise AirlockError("Unreviewed tool call")
        string(value.get("call_id"), "Call ID")
        string(value.get(field), "Tool input")
    elif kind in {"function_call_output", "custom_tool_call_output"} and not output:
        obj(value, common | {"call_id", "name", "namespace", "output"}, "tool result")
        string(value.get("call_id"), "Call ID")
        if value.get("name") is not None and value["name"] not in LOCAL_TOOLS:
            raise AirlockError("Unreviewed tool result")
        if value.get("namespace") not in {None, "functions"}:
            raise AirlockError("Unreviewed tool namespace")
        content(value.get("output"))
    else:
        raise AirlockError("Unsupported Responses item: " + str(kind))


def check_request(raw, profile):
    if len(raw) > profile["max_input_bytes"]:
        raise AirlockError("Responses input exceeds the approved bound")
    try:
        request = loads_no_duplicate_keys(raw, max_bytes=profile["max_input_bytes"])
        json.dumps(request, allow_nan=False)
        obj(request, REQUEST_FIELDS, "Responses request")
        if request.get("model") not in profile["models"]:
            raise AirlockError("Model is outside approved authority")
        if request.get("store") is not False or type(request.get("stream")) is not bool:
            raise AirlockError("Responses requires explicit no-storage and boolean streaming")
        cap = request.get("max_output_tokens", profile["max_output_tokens"])
        if type(cap) is not int or not 16 <= cap <= profile["max_output_tokens"]:
            raise AirlockError("Responses output exceeds approved bound")
        if (
            request.get("tool_choice", "auto") not in {"auto", "none"}
            or type(request.get("parallel_tool_calls", False)) is not bool
        ):
            raise AirlockError("Unsupported tool control")
        tools(request.get("tools", []))
        if not isinstance(request.get("input"), list):
            raise AirlockError("Responses requires inline conversation history")
        for entry in request["input"]:
            item(entry)
        if "instructions" in request:
            string(request["instructions"], "Instructions")
        if request.get("include", []) not in ([], ["reasoning.encrypted_content"]):
            raise AirlockError("Unsupported Responses include")
        if request.get("reasoning") is not None:
            reasoning = obj(
                request["reasoning"], {"effort", "summary", "context"}, "reasoning control"
            )
            if (
                reasoning.get("effort", "low")
                not in {"none", "minimal", "low", "medium", "high", "xhigh"}
                or reasoning.get("summary") not in {None, "auto", "concise", "detailed"}
                or reasoning.get("context") not in {None, "all_turns", "current_turn"}
            ):
                raise AirlockError("Unsupported reasoning control")
        if "text" in request:
            text = obj(request["text"], {"verbosity", "format"}, "text control")
            if text.get("verbosity") not in {None, "low", "medium", "high"}:
                raise AirlockError("Unsupported verbosity")
            if "format" in text:
                fmt = obj(text["format"], {"type", "name", "schema", "strict"}, "text format")
                if (
                    fmt.get("type") != "json_schema"
                    or not isinstance(fmt.get("schema"), dict)
                    or type(fmt.get("strict")) is not bool
                ):
                    raise AirlockError("Unsupported structured output")
                string(fmt.get("name"), "Schema name")
        # Cache/trace IDs are diagnostics, never authority or retry identity.
        if "prompt_cache_key" in request:
            string(request["prompt_cache_key"], "Cache key")
        if "client_metadata" in request:
            metadata = request["client_metadata"]
            if not isinstance(metadata, dict) or any(
                not isinstance(v, str) for v in metadata.values()
            ):
                raise AirlockError("Unsupported client metadata")
        request.pop("prompt_cache_key", None)
        request.pop("client_metadata", None)
        request["max_output_tokens"] = cap
        return canonical(request)
    except (ValueError, TypeError, RecursionError) as exc:
        raise AirlockError("Malformed or unsupported Responses request") from exc


def check_headers(headers, profile):
    if any(
        k.lower()
        not in {
            "content-type",
            "accept",
            "user-agent",
            "content-length",
            "connection",
            "accept-encoding",
        }
        for k in headers
    ):
        raise AirlockError("Header is outside the Responses contract")
    return {"Content-Type": "application/json", "Accept": "text/event-stream"}


def reservation(size, cap, prices):
    # Inline UTF-8 bytes, plus framing allowance; cache hits cannot loosen it.
    # This is a conservative signed-price estimate, not provider billing settlement.
    return cost(
        {"input_tokens": size + 4096, "output_tokens": cap},
        {**prices, "input": max(prices["input"], prices["cache_read"])},
    )


class _Rejected(ValueError):
    """Only fixed, content-free reason codes may enter observation diagnostics."""


def _require(ok, reason):
    if not ok:
        raise _Rejected(reason)


def _count(value):
    return type(value) is int and value >= 0


def _identifier(value):
    return isinstance(value, str) and bool(value)


def _output(value, *, partial=False):
    try:
        item(value, output=True)
    except AirlockError as exc:
        reason = {
            "Unsupported local tool call fields": "local-tool-fields",
            "Unsupported local tool caller": "local-tool-caller",
            "Unreviewed tool call": "unreviewed-tool-call",
        }.get(str(exc), "output-item-schema")
        raise _Rejected(reason) from exc
    _require(_identifier(value.get("id")), "output-item-id")
    _require(
        value.get("status") in ({None, "in_progress"} if partial else {None, "completed"}),
        "output-item-status",
    )
    kind = value["type"]
    if kind == "message":
        _require(isinstance(value["content"], list), "output-content-schema")
        _require(all(p["type"] == "output_text" for p in value["content"]), "output-content-type")
    elif kind == "reasoning":
        for field, part_type in (("summary", "summary_text"), ("content", "reasoning_text")):
            parts = value.get(field) or []
            _require(
                isinstance(parts, list) and all(p["type"] == part_type for p in parts),
                "reasoning-content-type",
            )
    else:
        _require(_identifier(value["call_id"]), "tool-call-id")
        if kind == "function_call" and not partial:
            try:
                args = loads_no_duplicate_keys(value["arguments"])
                json.dumps(args, allow_nan=False)
            except (ValueError, TypeError) as exc:
                raise _Rejected("function-arguments-json") from exc
            _require(isinstance(args, dict), "function-arguments-object")


# Response metadata from the documented direct Responses schema. These fields
# cannot add outbound authority; returned tools must still pass the local contract.
_RESPONSE_FIELDS = frozenset(
    {
        "id",
        "object",
        "model",
        "status",
        "output",
        "usage",
        "error",
        "incomplete_details",
        "created_at",
        "completed_at",
        "instructions",
        "metadata",
        "parallel_tool_calls",
        "temperature",
        "tool_choice",
        "tools",
        "top_p",
        "background",
        "max_output_tokens",
        "max_tool_calls",
        "previous_response_id",
        "prompt",
        "prompt_cache_key",
        "prompt_cache_retention",
        "reasoning",
        "text",
        "top_logprobs",
        "truncation",
        "user",
        "safety_identifier",
        "service_tier",
        "store",
        "access_programs",
    }
)


def _response(response, request):
    _require(isinstance(response, dict) and not set(response) - _RESPONSE_FIELDS, "response-schema")
    _require(response.get("object") == "response", "response-object")
    _require(response.get("model") == request["model"], "response-model")
    _require(
        response.get("background") in (None, False)
        and response.get("store") in (None, False)
        and response.get("access_programs") is None
        and response.get("previous_response_id") is None,
        "response-unsupported-state",
    )
    if response.get("max_output_tokens") is not None:
        _require(
            type(response["max_output_tokens"]) is int
            and response["max_output_tokens"] == request["max_output_tokens"],
            "response-output-cap",
        )
    try:
        tools(response.get("tools", []))
    except AirlockError as exc:
        raise _Rejected("response-tools") from exc


def _usage(response, request):
    _response(response, request)
    _require(response.get("object") == "response", "response-object")
    _require(_identifier(response.get("id")), "response-id")
    _require(response.get("model") == request["model"], "response-model")
    # An incomplete answer is not a confirmed completion, even if it reports usage.
    _require(response.get("status") == "completed", "response-not-completed")
    _require(
        response.get("error") is None and response.get("incomplete_details") is None,
        "response-error-or-incomplete",
    )
    _require(isinstance(response.get("output"), list), "response-output-schema")
    identities, calls = set(), set()
    for entry in response["output"]:
        _output(entry)
        _require(entry["id"] not in identities, "duplicate-output-id")
        identities.add(entry["id"])
        if "call_id" in entry:
            _require(entry["call_id"] not in calls, "duplicate-call-id")
            calls.add(entry["call_id"])
    usage = response.get("usage")
    _require(isinstance(usage, dict), "usage-missing")
    _require(
        not set(usage)
        - {
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "input_tokens_details",
            "output_tokens_details",
        },
        "usage-schema",
    )
    inp, out, total = (usage.get(k) for k in ("input_tokens", "output_tokens", "total_tokens"))
    _require(all(_count(n) for n in (inp, out, total)), "usage-count")
    _require(total == inp + out, "usage-total")
    _require(out <= request["max_output_tokens"], "usage-output-bound")
    _require(inp <= len(canonical(request)) + 4096, "usage-input-bound")
    details = usage.get("input_tokens_details", {})
    _require(
        isinstance(details, dict) and not set(details) - {"cached_tokens"}, "usage-input-details"
    )
    cached = details.get("cached_tokens", 0)
    _require(_count(cached) and cached <= inp, "usage-cache-count")
    details = usage.get("output_tokens_details", {})
    _require(
        isinstance(details, dict) and not set(details) - {"reasoning_tokens"},
        "usage-output-details",
    )
    reasoning = details.get("reasoning_tokens", 0)
    _require(_count(reasoning) and reasoning <= out, "usage-reasoning-count")
    return {
        "input_tokens": inp - cached,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": cached,
        "output_tokens": out,
    }


# Supported event families are explicit. No hosted tool or unknown event is ignored.
_PARTS = {"content_part": "content", "reasoning_summary_part": "summary"}
_TEXT = {
    "output_text": ("content", "output_text"),
    "reasoning_summary_text": ("summary", "summary_text"),
    "reasoning_text": ("content", "reasoning_text"),
}
_TOOL = {
    "function_call_arguments": ("function_call", "arguments"),
    "custom_tool_call_input": ("custom_tool_call", "input"),
}
_EVENTS = {
    "response.created",
    "response.in_progress",
    "response.completed",
    "response.incomplete",
    "response.output_item.added",
    "response.output_item.done",
} | {
    "response." + family + "." + suffix
    for families, suffixes in (
        (_PARTS, ("added", "done")),
        (_TEXT, ("delta", "done")),
        (_TOOL, ("delta", "done")),
    )
    for family in families
    for suffix in suffixes
}


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


class _Trace:
    def __init__(self, body):
        self.data = {
            "schema": "actenon-airlock/responses-observation/v1",
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "events": [],
            "event_count": 0,
        }
        self.hash = hashlib.sha256()
        self.records = []

    def record(self, event):
        kind = event.get("type")
        record = {"type": kind if isinstance(kind, str) and kind in _EVENTS else "unsupported"}
        if record["type"] == "unsupported":
            record["type_sha256"] = _hash(kind)
        for name in ("sequence_number", "output_index", "content_index", "summary_index"):
            if name in event:
                record[name] = event[name] if _count(event[name]) else "invalid"
        for name, value in (
            ("item_id", event.get("item_id")),
            (
                "item_id",
                event.get("item", {}).get("id") if isinstance(event.get("item"), dict) else None,
            ),
            (
                "response_id",
                event.get("response", {}).get("id")
                if isinstance(event.get("response"), dict)
                else None,
            ),
        ):
            if value is not None:
                record[name + "_sha256"] = _hash(value)
        if isinstance(event.get("item"), dict):
            item_kind = event["item"].get("type")
            record["item_type"] = (
                item_kind
                if item_kind in ("message", "reasoning", "function_call", "custom_tool_call")
                else "unsupported"
            )
        if kind in ("response.completed", "response.incomplete"):
            status = (
                event.get("response", {}).get("status")
                if isinstance(event.get("response"), dict)
                else None
            )
            self.data["terminal_status"] = (
                status
                if status in ("completed", "incomplete", "failed", "in_progress")
                else "invalid"
            )
        self.hash.update(json.dumps(record, sort_keys=True).encode() + b"\n")
        self.records.append(record)
        self.data["event_count"] += 1
        if len(self.data["events"]) < 256:
            self.data["events"].append(record)
        else:
            self.data["events_truncated"] = True
        self.data["events_sha256"] = self.hash.hexdigest()


def _events(body, trace):
    text = body.decode().replace("\r\n", "\n")
    _require(text.endswith("\n\n"), "sse-truncated-frame")
    result = []
    for block in text.split("\n\n"):
        name, data = None, []
        for line in block.split("\n"):
            if not line or line.startswith(":"):
                continue
            if line.startswith("event:"):
                _require(name is None, "sse-duplicate-event-name")
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].removeprefix(" "))
            else:
                raise _Rejected("sse-unsupported-field")
        if not data and name is None:
            continue
        event = loads_no_duplicate_keys("\n".join(data))
        json.dumps(event, allow_nan=False)
        _require(isinstance(event, dict), "event-not-object")
        trace.record(event)
        _require(name is None or name == event.get("type"), "sse-event-name-mismatch")
        result.append(event)
    return result


def _stream_response(events, request, trace):
    _require(bool(events), "stream-empty")
    _require(events[0].get("type") == "response.created", "stream-created-missing")
    response = events[0]["response"]
    _require(isinstance(response, dict) and _identifier(response.get("id")), "created-response-id")
    response_id = response["id"]
    added, completed, parts, chunks, finished = {}, {}, {}, {}, set()
    ids = set()
    previous = None
    terminal = None
    for position, event in enumerate(events):
        trace.data["checked_event"] = position
        trace.data["checked_event_metadata"] = trace.records[position]
        kind = event.get("type")
        _require(isinstance(kind, str) and kind in _EVENTS, "unsupported-event-type")
        seq = event.get("sequence_number")
        _require(_count(seq) and (previous is None or seq == previous + 1), "event-sequence")
        previous = seq
        trace.data["checked_sequence_number"] = seq
        _require(terminal is None, "event-after-terminal")
        common = {"type", "sequence_number"}
        if kind in {
            "response.created",
            "response.in_progress",
            "response.completed",
            "response.incomplete",
        }:
            _require(not set(event) - common - {"response"}, "response-event-schema")
            current = event["response"]
            _response(current, request)
            _require(current.get("id") == response_id, "response-id-mismatch")
            _require(current.get("model") == request["model"], "response-model-mismatch")
            _require(current.get("object") == "response", "response-object")
            if kind in {"response.completed", "response.incomplete"}:
                _require(
                    kind == "response.completed" and current.get("status") == "completed",
                    "response-not-completed",
                )
                terminal = current
            else:
                _require(kind != "response.created" or position == 0, "duplicate-created")
                _require(
                    current.get("status") == "in_progress"
                    and current.get("output") == []
                    and current.get("usage") is None
                    and not added,
                    "response-progress-state",
                )
                _require(
                    current.get("error") is None and current.get("incomplete_details") is None,
                    "response-error-or-incomplete",
                )
            continue
        index = event.get("output_index")
        _require(_count(index), "output-index")
        if kind in {"response.output_item.added", "response.output_item.done"}:
            _require(not set(event) - common - {"output_index", "item"}, "output-event-schema")
            value = event["item"]
            if kind.endswith("added"):
                _require(index == len(added), "output-add-order")
                _output(value, partial=True)
                _require(value["id"] not in ids, "duplicate-output-id")
                for field in ("arguments", "input", "content", "summary"):
                    if field in value:
                        _require(value[field] in ("", [], None), "output-initial-content")
                ids.add(value["id"])
                added[index] = value
            else:
                _require(index in added and index not in completed, "output-done-order")
                _output(value)
                first = added[index]
                for key in (
                    "id",
                    "type",
                    "call_id",
                    "name",
                    "namespace",
                    "role",
                    "phase",
                    "caller",
                ):
                    _require(first.get(key) == value.get(key), "output-item-identity")
                for key, partial in chunks.items():
                    if key[0] != index:
                        continue
                    _require(key in finished, "delta-done-missing")
                    field, part_index = key[1:]
                    final = value[field] if part_index is None else value[field][part_index]["text"]
                    _require("".join(partial) == final, "delta-final-mismatch")
                for key, part in parts.items():
                    if key[0] == index:
                        _require(
                            part["done"] and part["value"] == value[key[1]][key[2]],
                            "part-final-mismatch",
                        )
                if value["type"] in {"function_call", "custom_tool_call"}:
                    field = "arguments" if value["type"] == "function_call" else "input"
                    _require((index, field, None) in finished, "tool-input-done-missing")
                for field in ("content", "summary"):
                    for part_index, final_part in enumerate(value.get(field) or []):
                        _require((index, field, part_index) in parts, "part-completion-missing")
                completed[index] = value
            continue
        _require(index in added and index not in completed, "event-outside-item")
        value = added[index]
        _require(event.get("item_id") == value["id"], "event-item-id")
        family, suffix = kind[len("response.") :].rsplit(".", 1)
        allowed = common | {"output_index", "item_id"}
        if family in _TOOL:
            item_kind, field = _TOOL[family]
            _require(value["type"] == item_kind, "tool-event-type")
            key = (index, field, None)
            payload = "delta" if suffix == "delta" else field
        else:
            field = _PARTS.get(family) or _TEXT[family][0]
            index_field = "summary_index" if field == "summary" else "content_index"
            part_index = event.get(index_field)
            _require(_count(part_index), "part-index")
            expected_kind = (
                "reasoning" if field == "summary" or family == "reasoning_text" else "message"
            )
            _require(
                value["type"] == expected_kind
                or (family == "content_part" and value["type"] == "reasoning"),
                "part-item-type",
            )
            key = (index, field, part_index)
            allowed.add(index_field)
            payload = "part" if family in _PARTS else "delta" if suffix == "delta" else "text"
            if family in _TEXT:
                _require(key in parts and not parts[key]["done"], "text-outside-part")
                expected = _TEXT[family][1]
                _require(parts[key]["value"]["type"] == expected, "text-part-type")
                allowed.add("logprobs")
                _require(event.get("logprobs", []) == [], "unsupported-logprobs")
        allowed.add(payload)
        # Documented random padding on delta events contains no execution data.
        if suffix == "delta":
            allowed.add("obfuscation")
            _require(isinstance(event.get("obfuscation", ""), str), "delta-obfuscation-type")
        _require(not set(event) - allowed, "event-schema")
        if family in _PARTS:
            part = event["part"]
            content([part])
            if suffix == "added":
                _require(
                    key not in parts and key[2] == sum(k[:2] == key[:2] for k in parts),
                    "part-add-order",
                )
                _require(part.get("text") == "", "part-initial-text")
                parts[key] = {"value": part, "done": False}
            else:
                _require(
                    key in parts and not parts[key]["done"] and key in finished, "part-done-order"
                )
                _require(
                    part["type"] == parts[key]["value"]["type"]
                    and part["text"] == "".join(chunks[key]),
                    "part-text-mismatch",
                )
                parts[key] = {"value": part, "done": True}
        else:
            _require(isinstance(event[payload], str), "delta-value-type")
            _require(key not in finished, "duplicate-text-done")
            if suffix == "delta":
                chunks.setdefault(key, []).append(event[payload])
            else:
                _require("".join(chunks.get(key, [])) == event[payload], "delta-done-mismatch")
                chunks.setdefault(key, [])
                finished.add(key)
    _require(terminal is not None, "terminal-missing")
    _require(len(added) == len(completed), "output-done-missing")
    _require(
        [completed[i] for i in range(len(added))] == terminal.get("output"),
        "terminal-output-mismatch",
    )
    return terminal


@dataclass(frozen=True)
class ResponsesObservation(Observation):
    diagnostics: dict | None = None


def observe(status, body, request):
    trace = _Trace(body)
    try:
        _require(len(body) <= 4 * 1024 * 1024, "response-byte-bound")
        if status == 429:
            error = loads_no_duplicate_keys(body)["error"]
            return ResponsesObservation(
                declined=error.get("code") in {"rate_limit_exceeded", "insufficient_quota"}
            )
        _require(status == 200, "http-status")
        if request["stream"]:
            response = _stream_response(_events(body, trace), request, trace)
        else:
            response = loads_no_duplicate_keys(body)
            json.dumps(response, allow_nan=False)
        usage = _usage(response, request)
        trace.data.update(rejection_reason=None, validated_usage=usage)
        return ResponsesObservation(confirmed=True, usage=usage, diagnostics=trace.data)
    except _Rejected as exc:
        trace.data["rejection_reason"] = str(exc)
    except AirlockError:
        trace.data["rejection_reason"] = "content-schema"
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError):
        trace.data["rejection_reason"] = "malformed-response"
    return ResponsesObservation(diagnostics=trace.data)
