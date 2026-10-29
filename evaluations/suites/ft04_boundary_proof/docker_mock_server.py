import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

AUDIT = {
    "health_count": 0,
    "forbidden_delete_count": 0,
    "model_requests_count": 0,
    "received_auth_headers": [],
    "requests": []
}

class MockServerHandler(BaseHTTPRequestHandler):
    def _record(self, method):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        auth = self.headers.get("Authorization", "")
        entry = {
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        }
        AUDIT["requests"].append(entry)
        if auth:
            AUDIT["received_auth_headers"].append(auth)
        return entry, body

    def do_GET(self):
        if self.path == "/__audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            data = json.dumps(AUDIT).encode("utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self._record("GET")
        if self.path == "/health":
            AUDIT["health_count"] += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            data = b'{"status": "ok"}'
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/__reset":
            AUDIT["health_count"] = 0
            AUDIT["forbidden_delete_count"] = 0
            AUDIT["model_requests_count"] = 0
            AUDIT["received_auth_headers"].clear()
            AUDIT["requests"].clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            data = b'{"reset": true}'
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        entry, body = self._record("POST")
        if self.path == "/v1/chat/completions":
            AUDIT["model_requests_count"] += 1
            resp = {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "test-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "POSITIVE_BROKER_INFERENCE_SUCCESS"
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 5,
                    "total_tokens": 17
                }
            }
            data = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        self._record("DELETE")
        if self.path == "/critical-resource":
            AUDIT["forbidden_delete_count"] += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            data = b'{"deleted": true, "critical_destroyed": true}'
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        sys.stderr.write(f"[DOCKER-MOCK] {format % args}\n")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), MockServerHandler)
    print("Docker Mock Server running on 0.0.0.0:8080", flush=True)
    server.serve_forever()
