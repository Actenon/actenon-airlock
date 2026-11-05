"""The reviewed Anthropic Messages contract for an unchanged coding agent.

Agent traffic is richer than text inference: tools, tool results, block system prompts
and streaming. Each shape here was observed from the pinned agent or is a documented
form of one. Anything else is refused, because some Messages features make the provider
itself act. Server tools fetch URLs and run code, `mcp_servers` reaches remote servers,
and URL and file sources pull content in. Each would be a route around the supervisor,
so none has a place in this contract.

Bodies are forwarded byte for byte after a strict parse: re-encoding could read as an
edit of model history. Refusing duplicate keys and non-finite numbers keeps the provider
from reading different bytes than the ones checked here.

Model output is data. A tool call in a reply authorizes nothing and nothing here acts on
one; the agent runs it inside its own boundary. Costs are estimates from signed prices
and provider-reported usage, never billing settlement.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from actenon.core.json import loads_no_duplicate_keys

from . import provider_errors
from .common import AirlockError

CONTRACT = "anthropic-agent/v1"
ANTHROPIC_VERSION = "2023-06-01"
MAX_OUTPUT_TOKENS = 64000
MAX_INPUT_BYTES = 3 * 1024 * 1024
PRICES = ("input", "cache_write", "cache_read", "output")
PROFILE_FIELDS = frozenset(
    {
        "contract",
        "max_input_bytes",
        "anthropic_betas",
        "price_microusd_per_mtok",
        "max_run_microusd",
    }
)
_BETA = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")

_REQUEST = frozenset(
    {
        "model",
        "messages",
        "max_tokens",
        "system",
        "tools",
        "tool_choice",
        "stream",
        "metadata",
        "thinking",
        "output_config",
        "stop_sequences",
    }
)
_TEXT = frozenset({"type", "text", "cache_control"})
_CONTENT = {
    "text": _TEXT,
    "image": frozenset({"type", "source", "cache_control"}),
    "document": frozenset({"type", "source", "title", "context", "cache_control"}),
    "tool_use": frozenset({"type", "id", "name", "input", "cache_control"}),
    "tool_result": frozenset({"type", "tool_use_id", "content", "is_error", "cache_control"}),
    "thinking": frozenset({"type", "thinking", "signature"}),
    "redacted_thinking": frozenset({"type", "data"}),
}
_ROLES = {
    "user": frozenset({"text", "image", "document", "tool_result"}),
    "assistant": frozenset({"text", "tool_use", "thinking", "redacted_thinking"}),
    "system": frozenset({"text"}),
}
_RESULT_CONTENT = frozenset({"text", "image", "document"})
# base64 and text carry their bytes inline. URL and file sources make the provider fetch.
_SOURCES = {"image": frozenset({"base64"}), "document": frozenset({"base64", "text"})}
_EFFORT = frozenset({"low", "medium", "high", "xhigh", "max"})
_THINKING = frozenset({"adaptive", "between_tools", "disabled"})
_TOOL_CHOICE = frozenset({"auto", "none", "any", "tool"})
_REPLY_BLOCKS = frozenset({"text", "tool_use", "thinking", "redacted_thinking"})
_STOP_REASONS = frozenset(
    {
        "end_turn",
        "max_tokens",
        "stop_sequence",
        "tool_use",
        "refusal",
        "model_context_window_exceeded",
    }
)
_DELTAS = frozenset(
    {"text_delta", "input_json_delta", "thinking_delta", "signature_delta", "citations_delta"}
)
_DECLINED = {429: "rate_limit_error", 529: "overloaded_error"}
_COUNTS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
)


def validate_agent_profile(profile: dict) -> dict:
    """Bounds a reviewer signs. Each is enforced by the supervisor, never by the agent."""
    if profile.get("contract") != CONTRACT or profile.get("provider") != "anthropic":
        raise AirlockError("Unsupported agent inference contract")
    bound = profile.get("max_output_tokens")
    if type(bound) is not int or not 1 <= bound <= MAX_OUTPUT_TOKENS:
        raise AirlockError(f"Agent output bound must be between 1 and {MAX_OUTPUT_TOKENS}")
    size = profile.get("max_input_bytes")
    if type(size) is not int or not 1 <= size <= MAX_INPUT_BYTES:
        raise AirlockError(f"Agent input bound must be between 1 and {MAX_INPUT_BYTES} bytes")
    betas = profile.get("anthropic_betas")
    if (
        not isinstance(betas, list)
        or len(set(map(str, betas))) != len(betas)
        or not all(isinstance(flag, str) and _BETA.match(flag) for flag in betas)
    ):
        raise AirlockError("Model features must be a list of exact beta names")
    prices = profile.get("price_microusd_per_mtok")
    if (
        not isinstance(prices, dict)
        or set(prices) != set(PRICES)
        or any(type(value) is not int or value < 0 for value in prices.values())
    ):
        raise AirlockError("Model prices must give every token class as whole micro-USD")
    limit = profile.get("max_run_microusd")
    if type(limit) is not int or limit < 1:
        raise AirlockError("A positive per-run model spend bound is required")
    return profile


def bounds_expanded(new: dict, old: dict) -> bool:
    """Whether a reviewer must look again. Lower prices would loosen the spend bound."""
    return (
        bool(set(new["anthropic_betas"]) - set(old["anthropic_betas"]))
        or new["max_input_bytes"] > old["max_input_bytes"]
        or new["max_run_microusd"] > old["max_run_microusd"]
        or any(
            new["price_microusd_per_mtok"][name] < old["price_microusd_per_mtok"][name]
            for name in PRICES
        )
    )


def _object(value, allowed, label: str) -> dict:
    if not isinstance(value, dict):
        raise AirlockError(f"{label} must be an object")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise AirlockError(f"{label} field is outside the agent contract: {unknown[0]}")
    return value


def _string(value, label: str) -> None:
    if not isinstance(value, str):
        raise AirlockError(f"{label} must be a string")


def _cache_control(block: dict) -> None:
    if "cache_control" not in block:
        return
    control = _object(block["cache_control"], frozenset({"type", "ttl"}), "cache_control")
    if control.get("type") != "ephemeral" or control.get("ttl", "5m") != "5m":
        raise AirlockError("Only 5-minute ephemeral cache control is supported")


def _source(block: dict) -> None:
    source = _object(
        block.get("source"), frozenset({"type", "media_type", "data"}), block["type"] + " source"
    )
    if source.get("type") not in _SOURCES[block["type"]]:
        raise AirlockError("Provider-fetched content sources are outside the agent contract")
    _string(source.get("data"), "Inline content")
    _string(source.get("media_type"), "Media type")


def _block(block, allowed: frozenset, label: str) -> None:
    if not isinstance(block, dict) or block.get("type") not in allowed:
        kind = block.get("type") if isinstance(block, dict) else type(block).__name__
        raise AirlockError(f"{label} block is outside the agent contract: {kind}")
    kind = block["type"]
    _object(block, _CONTENT[kind], kind + " block")
    _cache_control(block)
    if kind == "text":
        _string(block.get("text"), "Text")
    elif kind in _SOURCES:
        _source(block)
    elif kind == "tool_use":
        _string(block.get("id"), "Tool call ID")
        _string(block.get("name"), "Tool call name")
        if not isinstance(block.get("input"), dict):
            raise AirlockError("Tool call input must be an object")
    elif kind == "tool_result":
        _string(block.get("tool_use_id"), "Tool result ID")
        content = block.get("content", "")
        if not isinstance(content, str):
            if not isinstance(content, list):
                raise AirlockError("Tool result content must be text or blocks")
            for item in content:
                _block(item, _RESULT_CONTENT, "Tool result")
        if not isinstance(block.get("is_error", False), bool):
            raise AirlockError("Tool result error flag must be a boolean")
    elif kind == "thinking":
        _string(block.get("thinking"), "Thinking")
        _string(block.get("signature"), "Thinking signature")
    else:
        _string(block.get("data"), "Redacted thinking")


def _content(content, allowed: frozenset, label: str) -> None:
    if isinstance(content, str):
        return
    if not isinstance(content, list):
        raise AirlockError(f"{label} content must be text or blocks")
    for block in content:
        _block(block, allowed, label)


def _tool(tool) -> None:
    allowed = frozenset({"type", "name", "description", "input_schema", "cache_control"})
    if isinstance(tool, dict) and tool.get("type", "custom") != "custom":
        raise AirlockError("Provider-executed tools are outside the agent contract")
    _object(tool, allowed, "Tool")
    _cache_control(tool)
    _string(tool.get("name"), "Tool name")
    _string(tool.get("description", ""), "Tool description")
    if not isinstance(tool.get("input_schema"), dict):
        raise AirlockError("Tool input schema must be an object")


def check_request(raw: bytes, profile: dict) -> dict:
    """Refuse anything outside the contract. The caller forwards `raw` unchanged."""
    if len(raw) > profile["max_input_bytes"]:
        raise AirlockError("Model input exceeds the approved byte bound")
    try:
        request = loads_no_duplicate_keys(raw, max_bytes=profile["max_input_bytes"])
        json.dumps(request, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise AirlockError("Model request is not strict JSON") from exc
    _object(request, _REQUEST, "Model request")
    if request.get("model") not in profile["models"]:
        raise AirlockError("Model is outside approved authority")
    tokens = request.get("max_tokens")
    if type(tokens) is not int or not 1 <= tokens <= profile["max_output_tokens"]:
        raise AirlockError("Model output exceeds the approved token bound")
    if not isinstance(request.get("stream", False), bool):
        raise AirlockError("Stream flag must be a boolean")
    messages = request.get("messages")
    if not isinstance(messages, list) or not messages:
        raise AirlockError("Model messages are required")
    for message in messages:
        _object(message, frozenset({"role", "content"}), "Message")
        allowed = _ROLES.get(message.get("role"))
        if allowed is None:
            raise AirlockError("Unsupported message role")
        _content(message.get("content"), allowed, "Message")
    _content(request.get("system", ""), frozenset({"text"}), "System")
    tools = request.get("tools", [])
    if not isinstance(tools, list):
        raise AirlockError("Tools must be a list")
    for tool in tools:
        _tool(tool)
    if "tool_choice" in request:
        choice = _object(
            request["tool_choice"],
            frozenset({"type", "name", "disable_parallel_tool_use"}),
            "Tool choice",
        )
        if choice.get("type") not in _TOOL_CHOICE:
            raise AirlockError("Unsupported tool choice")
    if "metadata" in request:
        user = _object(request["metadata"], frozenset({"user_id"}), "Metadata").get("user_id", "")
        _string(user, "Metadata user ID")
        if len(user) > 1024:
            raise AirlockError("Metadata user ID exceeds its bound")
    if "thinking" in request:
        thinking = _object(request["thinking"], frozenset({"type", "display"}), "Thinking")
        if thinking.get("type") not in _THINKING or thinking.get("display", "omitted") not in {
            "omitted",
            "summarized",
        }:
            raise AirlockError("Unsupported thinking mode")
    if "output_config" in request:
        effort = _object(request["output_config"], frozenset({"effort"}), "Output config")
        if effort.get("effort") not in _EFFORT:
            raise AirlockError("Unsupported effort level")
    stops = request.get("stop_sequences", [])
    if not isinstance(stops, list) or not all(isinstance(stop, str) for stop in stops):
        raise AirlockError("Stop sequences must be strings")
    return request


def check_headers(headers: dict, profile: dict) -> dict:
    """The fixed headers this contract sends, with only signed beta features."""
    checked = {"Content-Type": "application/json", "anthropic-version": ANTHROPIC_VERSION}
    for name, value in headers.items():
        lower = name.lower()
        if lower == "anthropic-beta":
            flags = [flag.strip() for flag in value.split(",") if flag.strip()]
            unknown = sorted(set(flags) - set(profile["anthropic_betas"]))
            if unknown:
                raise AirlockError("Model feature is outside approved authority: " + unknown[0])
            if flags:
                checked["anthropic-beta"] = ",".join(flags)
        elif lower == "content-type":
            if value.split(";")[0].strip().lower() != "application/json":
                raise AirlockError("Model requests must be JSON")
        elif lower != "anthropic-version" or value != ANTHROPIC_VERSION:
            raise AirlockError("HTTP header is outside the agent contract: " + lower)
    return checked


@dataclass(frozen=True)
class Observation:
    """What one reply showed. Only a complete, in-contract answer is confirmed."""

    confirmed: bool = False
    declined: bool = False
    usage: dict | None = None
    # Fixed-vocabulary status evidence for failed replies; never authority.
    diagnostics: dict | None = None


def _usage(raw: dict) -> dict | None:
    counts = {name: raw.get(name) or 0 for name in _COUNTS}
    if not all(type(value) is int and value >= 0 for value in counts.values()):
        return None
    if "input_tokens" not in raw or "output_tokens" not in raw:
        return None
    # A server tool ran despite the request contract, so this is not a plain answer.
    if any(value for value in (raw.get("server_tool_use") or {}).values()):
        return None
    return counts


def _events(text: str):
    for chunk in text.replace("\r\n", "\n").split("\n\n"):
        name, data = None, []
        for line in chunk.split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif line and not line.startswith(":"):
                raise ValueError("Malformed event stream")
        if name or data:
            yield name, json.loads("\n".join(data))


def _stream_usage(body: bytes, model: str) -> dict | None:
    """Follow the event grammar to its end. A cut or reordered stream confirms nothing."""
    usage, stop_reason, finished = None, None, False
    open_block, next_block = None, 0
    for name, event in _events(body.decode()):
        if name == "ping":
            continue
        if finished or event.get("type") != name:
            return None
        if name == "message_start":
            message = event["message"]
            if usage is not None or message["model"] != model or message["role"] != "assistant":
                return None
            usage = dict(message["usage"])
        elif usage is None:
            return None
        elif name == "content_block_start":
            kind = event["content_block"]["type"]
            if open_block is not None or event["index"] != next_block or kind not in _REPLY_BLOCKS:
                return None
            open_block = event["index"]
            next_block += 1
        elif name == "content_block_delta":
            if event["index"] != open_block or event["delta"]["type"] not in _DELTAS:
                return None
        elif name == "content_block_stop":
            if event["index"] != open_block:
                return None
            open_block = None
        elif name == "message_delta":
            stop_reason = event["delta"]["stop_reason"]
            usage.update(event["usage"])
        elif name == "message_stop":
            finished = True
        else:
            return None
    if not finished or open_block is not None or stop_reason not in _STOP_REASONS:
        return None
    return _usage(usage)


def _message_usage(body: bytes, model: str) -> dict | None:
    message = json.loads(body)
    if (
        message["model"] != model
        or message["role"] != "assistant"
        or message["stop_reason"] not in _STOP_REASONS
        or not all(block["type"] in _REPLY_BLOCKS for block in message["content"])
    ):
        return None
    return _usage(message["usage"])


def _declined(status: int, body: bytes) -> bool:
    try:
        reply = json.loads(body)
        return reply["type"] == "error" and reply["error"]["type"] == _DECLINED[status]
    except (ValueError, KeyError, TypeError):
        return False


def observe(status: int, body: bytes, request: dict) -> Observation:
    """Establish inference output, nothing about billing or what happens downstream."""
    if status != 200:
        diagnostics = provider_errors.status_diagnostic(status, body)
        if status in _DECLINED and _declined(status, body):
            return Observation(declined=True, diagnostics=diagnostics)
        return Observation(diagnostics=diagnostics)
    try:
        read = _stream_usage if request.get("stream") else _message_usage
        usage = read(body, request["model"])
    except (ValueError, KeyError, TypeError, AttributeError):
        return Observation()
    return Observation(confirmed=usage is not None, usage=usage)


def cost(usage: dict, prices: dict) -> int:
    """Micro-USD, rounded up, from signed prices. An estimate, not billing settlement."""
    total = (
        usage.get("input_tokens", 0) * prices["input"]
        + usage.get("cache_creation_input_tokens", 0) * prices["cache_write"]
        + usage.get("cache_read_input_tokens", 0) * prices["cache_read"]
        + usage.get("output_tokens", 0) * prices["output"]
    )
    return -(-total // 1_000_000)


def reservation(size: int, max_tokens: int, prices: dict) -> int:
    """A deliberately high estimate of one call, held until its usage is observed.

    Two bytes per token overstates ordinary prompts. A cached prefix makes the real cost
    lower still, so a run stops early rather than late.
    """
    return cost({"input_tokens": size // 2, "output_tokens": max_tokens}, prices)
