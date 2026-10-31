"""Untrusted convenience relay; containment does not depend on this program.

It offers model SDKs a loopback base URL and launches ordinary commands without
Python instrumentation. Removing or replacing it cannot restore network access.
"""

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LIMIT = 8 * 1024 * 1024
# The provider's own retry guidance. Everything else about a reply stays behind the bridge.
PASSED = ("retry-after", "x-should-retry", "request-id")
MODEL_TARGETS = {
    "/v1/chat/completions": "https://api.openai.com/v1/chat/completions",
    "/v1/messages": "https://api.anthropic.com/v1/messages",
}


def rpc(value):
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > LIMIT:
        raise ValueError("Request too large")
    with socket.socket(socket.AF_UNIX) as connection:
        # Cold starts and bounded text inference may take longer than frame transfer.
        # The supervisor still owns authorization, reservations and transport limits.
        connection.settimeout(660)
        connection.connect("/ipc/broker.sock")
        connection.sendall(struct.pack("!I", len(data)) + data)
        with connection.makefile("rb") as stream:
            header = stream.read(4)
            if len(header) != 4:
                raise EOFError("Supervisor unavailable")
            size = struct.unpack("!I", header)[0]
            if size > LIMIT:
                raise ValueError("Response too large")
            data = stream.read(size)
            if len(data) != size:
                raise EOFError("Incomplete supervisor response")
            return json.loads(data)


class Relay(BaseHTTPRequestHandler):
    def do_POST(self):
        route, _, query = self.path.partition("?")
        messages = route == "/v1/messages" and query in {"", "beta=true"}
        headers = {}
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > LIMIT // 2 or self.headers.get("Transfer-Encoding"):
                raise ValueError("Unsupported request framing")
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError("Incomplete request")
            if route == "/v1/messages/count_tokens":
                # Optional: the client estimates without it, so this is no refused effect.
                self.finish_reply(404, b'{"error":"Not offered"}', "application/json", headers)
                return
            target = MODEL_TARGETS.get(route if messages else self.path)
            if target is None:
                # The supervisor, not this relay, makes the authority decision.
                target = "https://api.openai.com" + self.path
            forwarded = {"Content-Type": "application/json"}
            if messages and self.headers.get("anthropic-beta"):
                forwarded["anthropic-beta"] = self.headers["anthropic-beta"]
            result = rpc(
                {
                    "kind": "protected-http",
                    "method": "POST",
                    "url": target,
                    "headers": forwarded,
                    "body": base64.b64encode(body).decode(),
                }
            )
            if not result.get("ok"):
                status = 403
                reason = result.get("reason", "Airlock denied")
                error = {"error": reason}
                if messages:
                    message = {"type": "permission_error", "message": reason}
                    error = {"type": "error", "error": message}
                content = json.dumps(error).encode()
                content_type = "application/json"
            else:
                response = result["response"]
                status = response["status"]
                content = base64.b64decode(response["body"], validate=True)
                content_type = response["headers"].get("content-type", "application/json")
                headers = {k: response["headers"][k] for k in PASSED if k in response["headers"]}
        except (ValueError, OSError, EOFError, KeyError):
            status, content, content_type = (
                503,
                b'{"error":"Airlock unavailable"}',
                "application/json",
            )
        self.finish_reply(status, content, content_type, headers)

    def finish_reply(self, status, content, content_type, headers):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *args):
        pass


def main():
    os.makedirs("/workspace/.home", exist_ok=True)
    os.makedirs("/workspace/.tmp", exist_ok=True)
    global MODEL_TARGETS
    with open("/airlock/model-targets.json", encoding="utf-8") as stream:
        MODEL_TARGETS = json.load(stream)
    relay = ThreadingHTTPServer(("127.0.0.1", 0), Relay)
    thread = threading.Thread(target=relay.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{relay.server_port}"
    environment = dict(os.environ)
    environment.update(
        OPENAI_BASE_URL=base + "/v1",
        OPENAI_API_BASE=base + "/v1",
        AIDER_OPENAI_API_BASE=base + "/v1",
        ANTHROPIC_BASE_URL=base,
        OPENAI_API_KEY="airlock-no-standing-credential",
        ANTHROPIC_API_KEY="airlock-no-standing-credential",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0="safe.directory",
        GIT_CONFIG_VALUE_0="/workspace",
    )
    try:
        return subprocess.call(sys.argv[1:], cwd="/workspace", env=environment)
    finally:
        relay.shutdown()
        relay.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
