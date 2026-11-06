"""Airlock's own effect ownership under races, process death, store failure and retries.

Every assertion counts what a real loopback provider received.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from test_broker import message

from actenon_airlock.broker import Broker
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import discover
from actenon_airlock.state import State

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process signals")


@pytest.fixture
def held_server():
    """Provider that records each POST and can hold it open before answering."""
    calls: list[str] = []
    release = threading.Event()
    release.set()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append(self.path)
            release.wait(30)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *args):
            pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    http.daemon_threads = True
    threading.Thread(target=http.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{http.server_port}", calls, release
    release.set()
    http.shutdown()
    http.server_close()


def _handle_in_child(root: str, item: dict, start, queue) -> None:
    state = State(Path(root))
    broker = Broker(state, discover(state.root))
    try:
        start.wait(30)
        queue.put(broker.handle(item)["ok"])
    finally:
        broker.close()


def _wait(predicate, timeout=20.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached"
        time.sleep(0.02)


def test_eight_processes_racing_one_effect_dispatch_once(project, held_server):
    url, calls, release = held_server
    release.clear()
    state = project(f'import requests\nrequests.post("{url}/pay")\n')
    ctx = multiprocessing.get_context("spawn")
    start, queue = ctx.Event(), ctx.Queue()
    procs = [
        ctx.Process(
            target=_handle_in_child, args=(str(state.root), message(url + "/pay"), start, queue)
        )
        for _ in range(8)
    ]
    for p in procs:
        p.start()
    time.sleep(2.0)  # let every process build its broker and park on the event
    start.set()
    _wait(lambda: len(calls) >= 1)
    time.sleep(1.0)  # give duplicates every chance to arrive while the first is held
    release.set()
    results = [queue.get(timeout=30) for _ in procs]
    for p in procs:
        p.join(timeout=30)
    assert len(calls) == 1, calls
    assert sorted(results) == [False] * 7 + [True]
    assert state.verify_receipts()["ok"]


def test_sigkill_after_dispatch_leaves_the_effect_owned(project, held_server):
    url, calls, release = held_server
    release.clear()
    state = project(f'import requests\nrequests.post("{url}/pay")\n')
    ctx = multiprocessing.get_context("spawn")
    start, queue = ctx.Event(), ctx.Queue()
    start.set()
    child = ctx.Process(
        target=_handle_in_child, args=(str(state.root), message(url + "/pay"), start, queue)
    )
    child.start()
    _wait(lambda: len(calls) == 1)
    os.kill(child.pid, signal.SIGKILL)  # no settlement, no finally blocks
    child.join(timeout=10)
    release.set()

    broker = Broker(state, discover(state.root))  # a restarted supervisor with a fresh grant
    try:
        assert not broker.handle(message(url + "/pay"))["ok"]
    finally:
        broker.close()
    assert len(calls) == 1
    verification = state.verify_receipts()
    assert verification["ok"]
    refusal = verification["rows"][-1]["row"]
    assert refusal["decision"] == "DENY" and refusal["execution_occurred"] is False


def _lost_response_project(project):
    url = "https://api.github.com/repos/acme/support/issues"
    state = project(f'import requests\nrequests.post("{url}")\n')
    calls = []

    def provider(request):
        calls.append(request)
        raise httpx.ReadTimeout("response lost after the provider may have committed")

    def attempt() -> bool:
        broker = Broker(state, discover(state.root))
        broker.http.close()
        broker.http = httpx.Client(transport=httpx.MockTransport(provider))
        try:
            return broker.handle(message(url))["ok"]
        finally:
            broker.close()

    return state, calls, attempt


@pytest.mark.parametrize("store", ["permit.sqlite3", "replay.sqlite3"])
def test_corrupted_effect_or_replay_store_fails_closed_before_dispatch(project, store):
    state, calls, attempt = _lost_response_project(project)
    assert not attempt()
    # WAL mode keeps pages in the -wal file, so corrupt both and drop the index.
    for suffix in ("", "-wal"):
        path = state.local / (store + suffix)
        if path.exists():
            path.write_bytes(b"this is not a database" * 64)
    (state.local / (store + "-shm")).unlink(missing_ok=True)
    with pytest.raises(Exception):  # noqa: B017 - any failure, as long as nothing is sent
        attempt()
    assert len(calls) == 1


@pytest.mark.parametrize("replacement", ["deleted", "empty-store"])
def test_lost_effect_store_refuses_to_run_instead_of_redispatching(project, replacement):
    state, calls, attempt = _lost_response_project(project)
    assert not attempt()
    assert len(calls) == 1
    for suffix in ("", "-wal", "-shm"):
        (state.local / ("permit.sqlite3" + suffix)).unlink(missing_ok=True)
    if replacement == "empty-store":
        from actenon_permit.state import SQLiteStore

        SQLiteStore(str(state.local / "permit.sqlite3")).close()
    with pytest.raises(AirlockError, match="effect store is missing"):
        attempt()
    with pytest.raises(AirlockError, match="effect store is missing"):  # stays refused
        attempt()
    assert len(calls) == 1


@pytest.mark.parametrize(
    "header",
    [
        "traceparent",
        "tracestate",
        "x-request-id",
        "x-correlation-id",
        "x-amzn-trace-id",
        "x-b3-traceid",
        "x-cloud-trace-context",
        "sentry-trace",
        "baggage",
        "user-agent",
    ],
)
def test_tracing_headers_cannot_mint_a_new_effect_after_a_lost_response(project, header):
    url = "https://api.github.com/repos/acme/support/issues"
    state = project(f'import requests\nrequests.post("{url}")\n')
    calls = []

    def provider(request):
        calls.append(request)
        raise httpx.ReadTimeout("response lost after the provider may have committed")

    def run(headers: dict) -> bool:
        broker = Broker(state, discover(state.root))
        broker.http.close()
        broker.http = httpx.Client(transport=httpx.MockTransport(provider))
        item = message(url)
        item["headers"] = headers
        try:
            return broker.handle(item)["ok"]
        finally:
            broker.close()

    assert not run({header: "attempt-1"})
    assert not run({header: "attempt-2-fresh-trace"})
    assert len(calls) == 1, f"{header} let a retry re-dispatch an ambiguous effect"


def test_header_dependent_operations_require_a_provider_contract(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/pay")\n')
    broker = Broker(state, discover(state.root))
    try:
        first = message(url + "/pay")
        first["headers"] = {"content-type": "application/json"}
        second = message(url + "/pay")
        second["headers"] = {"content-type": "text/plain"}
        assert broker.handle(first)["ok"] and not broker.handle(second)["ok"]
    finally:
        broker.close()
    assert len(calls) == 1


def test_missing_state_key_fails_closed(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/pay")\n')
    state.key_path.unlink()
    with pytest.raises((AirlockError, OSError, ValueError, KeyError, json.JSONDecodeError)):
        Broker(state, discover(state.root))
    assert calls == []
