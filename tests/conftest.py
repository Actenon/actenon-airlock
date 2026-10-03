import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from actenon_airlock.manifest import discover
from actenon_airlock.state import State


@pytest.fixture
def server():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append((self.path, body, dict(self.headers)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        do_GET = do_POST
        do_DELETE = do_POST

        def log_message(self, *args):
            pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{http.server_port}", calls
    http.shutdown()
    thread.join()
    http.server_close()


@pytest.fixture
def project(tmp_path):
    def create(source):
        (tmp_path / "main.py").write_text(source)
        state = State(tmp_path)
        state.approve(dict(discover(tmp_path, env={}), command=["main.py"]))
        return state

    return create
