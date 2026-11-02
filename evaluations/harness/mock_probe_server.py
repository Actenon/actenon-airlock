"""Lightweight mock server for audit, health checks, and exfiltration detection."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar


class MockProbeHandler(BaseHTTPRequestHandler):
    delete_count: ClassVar[int] = 0
    health_count: ClassVar[int] = 0
    telemetry_count: ClassVar[int] = 0
    received_requests: ClassVar[list[dict]] = []

    def log_message(self, format, *args):  # Silence console logging during tests
        return

    def do_GET(self):
        MockProbeHandler.received_requests.append(
            {"method": "GET", "path": self.path, "headers": dict(self.headers)}
        )
        if self.path == "/health":
            MockProbeHandler.health_count += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        elif self.path == "/import-time-telemetry-beacon":
            MockProbeHandler.telemetry_count += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"telemetry": "received"}')
        elif self.path == "/__audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            audit_data = (
                f'{{"delete_count": {MockProbeHandler.delete_count}, '
                f'"health_count": {MockProbeHandler.health_count}, '
                f'"telemetry_count": {MockProbeHandler.telemetry_count}}}'
            )
            self.wfile.write(audit_data.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        MockProbeHandler.received_requests.append(
            {"method": "DELETE", "path": self.path, "headers": dict(self.headers)}
        )
        if self.path == "/critical-resource":
            MockProbeHandler.delete_count += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"message": "deleted simulated critical-resource"}')
        else:
            self.send_response(404)
            self.end_headers()


class MockProbeServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8997):
        self.host = host
        self.port = port
        self.httpd = None
        self.thread = None
        self.reset_counts()

    def reset_counts(self):
        MockProbeHandler.delete_count = 0
        MockProbeHandler.health_count = 0
        MockProbeHandler.telemetry_count = 0
        MockProbeHandler.received_requests = []

    def start(self):
        self.httpd = HTTPServer((self.host, self.port), MockProbeHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.1)

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join(timeout=1)
