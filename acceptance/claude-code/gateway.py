"""The baseline's way to the model. Keeps the owner's API key out of its container.

The unrestricted baseline runs poisoned repositories on purpose, so it must not hold a
real key, and it has no supervisor to bound its spend. This host process adds the key
and stops at the same per-run bound. It is not a security boundary and enforces nothing
else: the baseline stays unrestricted, which is what makes it a baseline.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from actenon_airlock.agent_inference import ANTHROPIC_VERSION, cost, observe, reservation

UPSTREAM = "https://api.anthropic.com/v1/messages"
TIMEOUT_SECONDS = 540


class BaselineGateway:
    def __init__(self, *, limit_microusd: int, prices: dict, client=None):
        self.limit, self.prices = limit_microusd, prices
        self.spent = self.calls = 0
        self.http = client or httpx.Client(trust_env=False, timeout=TIMEOUT_SECONDS)
        key = os.environ["ANTHROPIC_API_KEY"]
        lock = threading.Lock()
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.path.partition("?")[0] != "/v1/messages":
                    return self.finish_reply(404, b'{"error":"Not offered"}', "application/json")
                request = json.loads(body)
                held = reservation(len(body), request.get("max_tokens", 0), gateway.prices)
                with lock:
                    if gateway.spent + held > gateway.limit:
                        return self.finish_reply(
                            403,
                            b'{"type":"error","error":{"type":"permission_error",'
                            b'"message":"Baseline spend bound reached"}}',
                            "application/json",
                        )
                    gateway.spent += held
                    gateway.calls += 1
                headers = {
                    "content-type": "application/json",
                    "anthropic-version": ANTHROPIC_VERSION,
                    "x-api-key": key,
                }
                if self.headers.get("anthropic-beta"):
                    headers["anthropic-beta"] = self.headers["anthropic-beta"]
                try:
                    reply = gateway.http.post(UPSTREAM, headers=headers, content=body)
                except httpx.HTTPError:
                    return self.finish_reply(502, b'{"error":"Upstream lost"}', "application/json")
                seen = observe(reply.status_code, reply.content, request)
                actual = 0 if seen.declined else held
                if seen.usage is not None:
                    actual = cost(seen.usage, gateway.prices)
                with lock:
                    gateway.spent += actual - held
                self.finish_reply(
                    reply.status_code,
                    reply.content,
                    reply.headers.get("content-type", "application/json"),
                    {
                        k: reply.headers[k]
                        for k in ("retry-after", "x-should-retry")
                        if k in reply.headers
                    },
                )

            def finish_reply(self, status, content, content_type, extra=None):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                for name, value in (extra or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.http.close()
