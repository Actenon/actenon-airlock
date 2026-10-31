"""A scripted Anthropic Messages provider. It stands in for transport, never for a model.

Passing against it shows the protocol works. It says nothing about what a real model
would choose to do, and it is not acceptance evidence.
"""

from __future__ import annotations

import json

import httpx

ENDPOINT = "https://api.anthropic.com/v1/messages"
MODEL = "claude-test-model"
USAGE = {"input_tokens": 100, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
PRICES = "2,2.5,0.2,10"
BETAS = ["claude-code-20250219", "effort-2025-11-24", "interleaved-thinking-2025-05-14"]


def text(value):
    return {"type": "text", "text": value}


def tool(identity, name, **arguments):
    return {"type": "tool_use", "id": identity, "name": name, "input": arguments}


def _event(kind, **value):
    data = json.dumps({"type": kind, **value}, separators=(",", ":"))
    return f"event: {kind}\ndata: {data}\n\n"


def _block_events(index, block):
    if block["type"] == "text":
        start, delta = {"type": "text", "text": ""}, {"type": "text_delta", "text": block["text"]}
    else:
        start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
    return [
        _event("content_block_start", index=index, content_block=start),
        _event("content_block_delta", index=index, delta=delta),
        _event("content_block_stop", index=index),
    ]


def stream_body(blocks, *, model=MODEL, stop_reason=None, output_tokens=20) -> bytes:
    stop = stop_reason or (
        "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
    )
    message = {
        "id": "msg_fixture",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [],
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {**USAGE, "output_tokens": 1},
    }
    events = [_event("message_start", message=message), _event("ping")]
    for index, block in enumerate(blocks):
        events += _block_events(index, block)
    events += [
        _event(
            "message_delta",
            delta={"stop_reason": stop, "stop_sequence": None},
            usage={"output_tokens": output_tokens},
        ),
        _event("message_stop"),
    ]
    return "".join(events).encode()


def stream_reply(blocks, **options) -> httpx.Response:
    return httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=stream_body(blocks, **options)
    )


class ScriptedProvider:
    """Answers each model call with the next step, and keeps what actually arrived."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        step = self.steps[min(len(self.requests), len(self.steps)) - 1]
        return step if isinstance(step, httpx.Response) else stream_reply(step)

    def bodies(self):
        return [json.loads(request.content) for request in self.requests]
