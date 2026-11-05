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
    result = [
        {
            "type": "response.created",
            "response": {**response, "status": "in_progress", "output": [], "usage": None},
        }
    ]
    for i, value in enumerate(output):
        partial = dict(value)
        if "status" in partial:
            partial["status"] = "in_progress"
        kind = value["type"]
        fields = {
            "message": "content",
            "reasoning": "summary",
            "function_call": "arguments",
            "custom_tool_call": "input",
        }
        field = fields[kind]
        partial[field] = [] if field in {"content", "summary"} else ""
        result.append({"type": "response.output_item.added", "output_index": i, "item": partial})
        ref = {"output_index": i, "item_id": value["id"]}
        if field in {"arguments", "input"}:
            family = "function_call_arguments" if field == "arguments" else "custom_tool_call_input"
            result.extend(
                [
                    {"type": f"response.{family}.delta", **ref, "delta": value[field]},
                    {"type": f"response.{family}.done", **ref, field: value[field]},
                ]
            )
        else:
            for j, part in enumerate(value[field]):
                summary = field == "summary"
                part_family = "reasoning_summary_part" if summary else "content_part"
                text_family = "reasoning_summary_text" if summary else "output_text"
                ref_part = {**ref, "summary_index" if summary else "content_index": j}
                result.extend(
                    [
                        {
                            "type": f"response.{part_family}.added",
                            **ref_part,
                            "part": {**part, "text": ""},
                        },
                        {
                            "type": f"response.{text_family}.delta",
                            **ref_part,
                            "delta": part["text"],
                        },
                        {"type": f"response.{text_family}.done", **ref_part, "text": part["text"]},
                        {"type": f"response.{part_family}.done", **ref_part, "part": part},
                    ]
                )
        result.append({"type": "response.output_item.done", "output_index": i, "item": value})
    result.append({"type": "response.completed", "response": response})
    return [{**event, "sequence_number": n} for n, event in enumerate(result)]


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
