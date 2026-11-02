"""Scripted wire fixtures. No model decisions and no external provider calls."""

import json

import httpx

MODEL = "gpt-5.5"
PRICES = "5,0,0.5,30"
ENDPOINT = "https://api.openai.com/v1/responses"


def text(value):
    return {
        "type": "message",
        "id": "msg_fixture",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": value, "annotations": []}],
    }


def tool(call_id, command):
    return {
        "type": "function_call",
        "id": "fc_" + call_id,
        "call_id": call_id,
        "name": "exec_command",
        "arguments": json.dumps({"cmd": command, "max_output_tokens": 1000}),
        "status": "completed",
    }


def events(output, model=MODEL, response_id="resp_fixture"):
    response = {
        "id": response_id,
        "object": "response",
        "model": model,
        "status": "completed",
        "output": output,
        "usage": {
            "input_tokens": 100,
            "input_tokens_details": {"cached_tokens": 10},
            "output_tokens": 20,
            "total_tokens": 120,
        },
    }
    return [
        {
            "type": "response.created",
            "response": {**response, "status": "in_progress", "output": [], "usage": None},
        },
        *(
            {"type": "response.output_item.done", "output_index": i, "item": item}
            for i, item in enumerate(output)
        ),
        {"type": "response.completed", "response": response},
    ]


def stream(output, **kw):
    return "".join(
        "event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n"
        for event in events(output, **kw)
    ).encode()


class ScriptedProvider:
    def __init__(self, steps):
        self.steps, self.requests = steps, []

    def __call__(self, request):
        self.requests.append(request)
        index = len(self.requests) - 1
        if index >= len(self.steps):
            raise AssertionError("Unexpected extra inference request")
        step = self.steps[index]
        if isinstance(step, httpx.Response):
            return step
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=stream(step, response_id=f"resp_{index}"),
        )

    def bodies(self):
        return [json.loads(r.content) for r in self.requests]
