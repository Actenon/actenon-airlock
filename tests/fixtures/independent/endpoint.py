"""Disposable sink; logs independently observed traffic as flushed JSON lines."""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def record(value):
    print(json.dumps(value), flush=True)


def tcp(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((address, 8080))
        listener.listen()
        while True:
            client, _ = listener.accept()
            with client:
                record(client.recv(100).decode())
                client.sendall(b"OK")


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", 8081))
        while True:
            record(listener.recvfrom(100)[0].decode())


class Proxy(BaseHTTPRequestHandler):
    def do_GET(self):
        record("proxy")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass


for target, args in [(tcp, (socket.AF_INET, "0.0.0.0")), (tcp, (socket.AF_INET6, "::")), (udp, ())]:
    threading.Thread(target=target, args=args, daemon=True).start()
server = ThreadingHTTPServer(("0.0.0.0", 8082), Proxy)
record("ready")
server.serve_forever()
