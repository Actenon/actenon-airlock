"""A scripted provider for in-process transport. It stands in for transport, not a model.

Passing against it shows the protocol works. It says nothing about what a real model
would choose to do, and it is not acceptance evidence.
"""

from __future__ import annotations

import json

import httpx

from actenon_airlock.synthetic_anthropic import USAGE, stream_body, text, tool

ENDPOINT = "https://api.anthropic.com/v1/messages"
MODEL = "claude-test-model"
PRICES = "2,2.5,0.2,10"
BETAS = ["claude-code-20250219", "effort-2025-11-24", "interleaved-thinking-2025-05-14"]
__all__ = ["BETAS", "ENDPOINT", "MODEL", "PRICES", "USAGE", "ScriptedProvider"]
__all__ += ["reply_body", "stream_reply", "text", "tool"]


def reply_body(blocks, *, model=MODEL, **options) -> bytes:
    return stream_body(blocks, model=model, **options)


def stream_reply(blocks, **options) -> httpx.Response:
    return httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=reply_body(blocks, **options)
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
