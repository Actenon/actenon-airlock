"""Reviewed Responses transport for unchanged Codex; model tools confer no authority.

Only inline text/history and named client-side tools are supported. The supervisor
adds an omitted output cap BEFORE Permit hashes the exact dispatch bytes. This API
contract does not support the ChatGPT-plan preview, which rejects that cap.
"""

from __future__ import annotations

import json

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
        obj(value, common | {"call_id", "name", "namespace", field}, "local tool call")
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


def _usage(response, request):
    if response.get("model") != request["model"] or response.get("status") not in {
        "completed",
        "incomplete",
    }:
        return None
    if (
        response["status"] == "incomplete"
        and response.get("incomplete_details", {}).get("reason") != "max_output_tokens"
    ):
        return None
    for entry in response["output"]:
        item(entry, output=True)
    usage = response["usage"]
    inp, out = usage["input_tokens"], usage["output_tokens"]
    cached = usage.get("input_tokens_details", {}).get("cached_tokens", 0)
    if (
        not all(type(n) is int and n >= 0 for n in (inp, out, cached))
        or cached > inp
        or out > request["max_output_tokens"]
    ):
        return None
    return {
        "input_tokens": inp - cached,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": cached,
        "output_tokens": out,
    }


def observe(status, body, request):
    try:
        if status == 429:
            error = loads_no_duplicate_keys(body)["error"]
            return Observation(
                declined=error.get("code") in {"rate_limit_exceeded", "insufficient_quota"}
            )
        if status != 200:
            return Observation()
        if not request["stream"]:
            usage = _usage(loads_no_duplicate_keys(body), request)
            return Observation(confirmed=usage is not None, usage=usage)
        events = []
        for block in body.decode().replace("\r\n", "\n").split("\n\n"):
            lines = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
            if lines:
                events.append(loads_no_duplicate_keys("\n".join(lines)))
        if (
            not events
            or events[0].get("type") != "response.created"
            or events[-1].get("type") not in {"response.completed", "response.incomplete"}
        ):
            return Observation()
        response = events[-1]["response"]
        if response["id"] != events[0]["response"]["id"]:
            return Observation()
        completed = []
        for event in events[1:-1]:
            kind = event["type"]
            if kind == "response.output_item.done":
                item(event["item"], output=True)
                completed.append(event["item"])
            elif kind not in {
                "response.in_progress",
                "response.output_item.added",
                "response.content_part.added",
                "response.content_part.done",
                "response.output_text.delta",
                "response.output_text.done",
                "response.function_call_arguments.delta",
                "response.function_call_arguments.done",
                "response.custom_tool_call_input.delta",
                "response.custom_tool_call_input.done",
                "response.reasoning_summary_part.added",
                "response.reasoning_summary_part.done",
                "response.reasoning_summary_text.delta",
                "response.reasoning_summary_text.done",
                "response.reasoning_text.delta",
                "response.reasoning_text.done",
            }:
                return Observation()
        if completed != response["output"]:
            return Observation()
        usage = _usage(response, request)
        return Observation(confirmed=usage is not None, usage=usage)
    except (AirlockError, ValueError, KeyError, TypeError, AttributeError):
        return Observation()
