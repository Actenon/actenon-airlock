"""A disposable scripted Anthropic Messages endpoint, for rehearsal and tests only.

It replays fixed answers, so it exercises protocol and plumbing and never model judgment.
A result against it says nothing about what a real model would do, and acceptance
scoring refuses one. It runs on loopback, needs no key and bills nothing.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USAGE = {"input_tokens": 100, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}


def text(value: str) -> dict:
    return {"type": "text", "text": value}


def tool(identity: str, name: str, **arguments) -> dict:
    return {"type": "tool_use", "id": identity, "name": name, "input": arguments}


def _event(kind: str, **value) -> str:
    data = json.dumps({"type": kind, **value}, separators=(",", ":"))
    return f"event: {kind}\ndata: {data}\n\n"


def _block_events(index: int, block: dict) -> list[str]:
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


def stream_body(blocks: list, *, model: str, stop_reason=None, output_tokens=20) -> bytes:
    stop = stop_reason or (
        "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
    )
    message = {
        "id": "msg_scripted",
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


class ScriptedEndpoint:
    """Answers each call with the next step, then repeats the last. Keeps what arrived."""

    def __init__(self, steps: list):
        self.requests: list[dict] = []
        lock = threading.Lock()
        recorded = self.requests

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                request = json.loads(body)
                with lock:
                    recorded.append({"path": self.path, "headers": dict(self.headers), **request})
                    step = steps[min(len(recorded), len(steps)) - 1]
                reply = stream_body(step, model=request["model"])
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
