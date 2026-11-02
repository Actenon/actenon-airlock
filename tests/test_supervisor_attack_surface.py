"""Adversarial attacks through the approved supervisor interface.

Every attack here drives ``Broker.handle()`` — the same code the contained
agent reaches through the bridge socket — rather than a lower-level unit.
Each attack is observed by an independent referee (a live loopback sink or a
mock transport that records what actually arrived at the provider) and ships
with a working positive control proving the supervisor still serves
legitimate traffic through the same path.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from test_broker import message

from actenon_airlock.broker import Broker
from actenon_airlock.manifest import discover


class _RefereeHandler(BaseHTTPRequestHandler):
    """Independent observer: records method, path, body and headers."""

    def _record(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.records.append((self.command, self.path, body, dict(self.headers)))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    do_POST = do_GET = do_PUT = do_DELETE = _record

    def log_message(self, *args):
        pass


@pytest.fixture
def referee():
    http = ThreadingHTTPServer(("127.0.0.1", 0), _RefereeHandler)
    http.records = []
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}", http.records
    finally:
        http.shutdown()
        thread.join()
        http.server_close()


def attack(
    url, *, method="POST", line=2, file="main.py", kind="http", locations=None, body=b"hello"
):
    """An agent-authored message with fully attacker-chosen metadata."""
    msg = message(url, method=method, file=file, line=line, body=body)
    msg["kind"] = kind
    if locations is not None:
        msg["locations"] = locations
    return msg


def last_receipt(state):
    return json.loads((state.local / "receipts.jsonl").read_text().splitlines()[-1])


def test_method_confusion_cannot_reuse_post_authority_for_get(project, referee):
    """Attack: the approved callsite is a POST, the agent asks for GET/DELETE.

    The method is part of the scanned power (http.post vs http.get), so
    reusing the POST callsite's location for another verb must not bind.
    The referee proves nothing new left the supervisor, and a source that
    genuinely calls GET is still served (positive control).
    """
    url, seen = referee
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        # Positive control: the approved POST is served and observed.
        assert broker.handle(attack(url + "/a", method="POST"))["ok"]
        assert [r[:3] for r in seen] == [("POST", "/a", b"hello")]

        # Attack: same URL, same claimed callsite, different verb.
        for method in ("GET", "DELETE", "PUT"):
            out = broker.handle(attack(url + "/a", method=method))
            assert not out["ok"], method
            row = last_receipt(state)
            assert row["decision"] == "DENY", method
            assert not row["credential_released"], method
            assert row["execution_occurred"] is not True, method
        # Referee: nothing but the legitimate POST ever arrived.
        assert [r[:3] for r in seen] == [("POST", "/a", b"hello")]
    finally:
        broker.close()

    # Positive control: a source that actually calls GET is served, and a
    # read-only operation stays repeatable (dedup never blocks usefulness).
    state = project(f'import requests\nrequests.get("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        assert broker.handle(attack(url + "/a", method="GET"))["ok"]
        assert broker.handle(attack(url + "/a", method="GET"))["ok"]
        assert [r[:3] for r in seen] == [
            ("POST", "/a", b"hello"),
            ("GET", "/a", b"hello"),
            ("GET", "/a", b"hello"),
        ]
    finally:
        broker.close()


def test_forged_locations_cannot_bootstrap_authority(project, referee):
    """Attack: agent-authored locations try to impersonate a scanned callsite.

    Runtime authority binds only when the claimed location resolves to
    exactly one scanned project callsite. Forged spans, foreign files and
    empty locations must resolve to nothing, and the referee must observe
    zero external effects. The true location still works (positive control).
    """
    url, seen = referee
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        attacks = [
            ([{"file": "main.py", "line": 1, "col": 1}], "the import line, not the call"),
            ([{"file": "ghost.py", "line": 2, "col": 1}], "a file that does not exist"),
            ([{"file": "main.py", "line": 2, "col": -1}], "a negative column"),
            ([{"file": "main.py", "line": 2, "col": 0}], "a zero column"),
            ([{"file": "main.py", "line": 99, "col": 1}], "a line beyond the file"),
            ([], "no location at all"),
        ]
        for locations, why in attacks:
            out = broker.handle(attack(url + "/a", locations=locations))
            assert not out["ok"], why
            row = last_receipt(state)
            assert row["decision"] == "DENY", why
        # Referee: no attack produced any external effect.
        assert seen == []

        # A true location with a forged extra entry appended still binds
        # through the true position, but the forgery must not widen
        # anything: the same claimed locations cannot reach a second,
        # unapproved target.
        both = [
            {"file": "main.py", "line": 2, "col": 1},
            {"file": "ghost.py", "line": 5, "col": 1},
        ]
        assert broker.handle(attack(url + "/a", locations=both))["ok"]
        assert not broker.handle(attack(url + "/b", locations=both))["ok"]
        row = last_receipt(state)
        assert row["decision"] == "DENY"
        # Referee: only the approved /a effect ever arrived.
        assert [r[:3] for r in seen] == [("POST", "/a", b"hello")]
    finally:
        broker.close()


def test_wide_span_covering_two_callsites_is_refused(project, referee):
    """Attack: a wide location span blurs which callsite is being used.

    A span that contains two scanned callsites must not bind, because the
    runtime request could then inherit either call's authority. The same
    span narrowed to one callsite works (positive control).
    """
    url, seen = referee
    source = f'import requests\nrequests.post("{url}/a")\nrequests.post("{url}/b")\n'
    state = project(source)
    broker = Broker(state, discover(state.root))
    try:
        # Attack: one span covering both the /a and /b callsites.
        out = broker.handle(
            attack(
                url + "/a",
                locations=[
                    {
                        "file": "main.py",
                        "line": 2,
                        "col": 1,
                        "end_line": 3,
                        "end_col": 40,
                    }
                ],
            )
        )
        assert not out["ok"]
        row = last_receipt(state)
        assert row["decision"] == "DENY"
        assert seen == []

        # Attack repeated for the /b target with the same wide span.
        assert not broker.handle(
            attack(
                url + "/b",
                locations=[
                    {
                        "file": "main.py",
                        "line": 2,
                        "col": 1,
                        "end_line": 3,
                        "end_col": 40,
                    }
                ],
            )
        )["ok"]
        assert seen == []

        # Positive control: the span narrowed to one callsite binds, and the
        # referee observes the exact approved target.
        assert broker.handle(
            attack(
                url + "/b",
                locations=[
                    {
                        "file": "main.py",
                        "line": 3,
                        "col": 1,
                        "end_line": 3,
                        "end_col": 40,
                    }
                ],
            )
        )["ok"]
        assert [r[:3] for r in seen] == [("POST", "/b", b"hello")]
    finally:
        broker.close()


def test_github_kind_cannot_ride_unrelated_http_authority(project, monkeypatch):
    """Attack: a GitHub consequence message through a run with no GitHub power.

    The supervisor's github channel is the approved path for exactly
    reviewed GitHub creations. A run whose scanned authority is an unrelated
    HTTP call must not dispatch a Contents write, no matter what message
    kind, method or URL the agent chooses. A source holding the exact
    Contents power is served and its effect is held exactly once (positive
    control), observed by a mock provider transport.
    """
    monkeypatch.setenv("GITHUB_TOKEN", "supervisor-held-secret")
    target = "https://api.github.com/repos/acme/project/contents/patches/fix.patch"
    seen = []

    def provider(request):
        seen.append((request.method, str(request.url)))
        return httpx.Response(201, json={"ok": True, "commit": "abc"})

    # Attack: no GitHub power anywhere in the reviewed source. The message
    # uses the real wire kind ("http"): a GitHub consequence is carried by
    # the URL's scanned power, not by a privileged message kind.
    state = project('import requests\nrequests.post("https://example.com/unrelated")\n')
    broker = Broker(state, discover(state.root))
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider), trust_env=False)
    try:
        out = broker.handle(attack(target, method="PUT", kind="http"))
        assert not out["ok"]
        row = last_receipt(state)
        assert row["decision"] == "DENY"
        assert not row["credential_released"]
        # A "github" wire kind does not exist at the broker and is refused.
        assert not broker.handle(attack(target, method="PUT", kind="github"))["ok"]
        # Referee: no provider was ever contacted.
        assert seen == []
    finally:
        broker.close()

    # Positive control: a source whose scanned power is exactly this
    # Contents creation is dispatched exactly once and the effect is held.
    state = project(f'import requests\nrequests.put("{target}")\n')
    broker = Broker(state, discover(state.root))
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider), trust_env=False)
    try:
        first = broker.handle(attack(target, method="PUT", kind="http"))
        assert first["ok"]
        assert first["outcome"] == "AMBIGUOUS"  # a 201 alone never means COMMITTED
        assert seen == [("PUT", target)]
        # A second identical attempt is refused as a duplicate effect.
        second = broker.handle(attack(target, method="PUT", kind="http"))
        assert not second["ok"]
        assert seen == [("PUT", target)]
        row = last_receipt(state)
        assert row["decision"] == "DENY"
        assert "already reserved" in row["reason"]
        # The supervisor-held credential never appears in the evidence.
        assert "supervisor-held-secret" not in (state.local / "receipts.jsonl").read_text()
    finally:
        broker.close()


def test_unknown_and_malformed_messages_fail_closed(project, referee):
    """Attack: unknown kinds, malformed fields and credential-bearing URLs.

    Every malformed message must be refused with a denial receipt rather
    than crash the supervisor or dispatch anything; the referee observes
    zero effects, and the legitimate request still works (positive control).
    """
    url, seen = referee
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        hostile = []
        for kind in ("shell", "exec", "subprocess", "fetch", "", "HTTP", "Http"):
            msg = attack(url + "/a")
            msg["kind"] = kind
            hostile.append((msg, f"kind={kind!r}"))
        msg = attack(url + "/a")
        msg["headers"] = "not-a-dict"
        hostile.append((msg, "headers not an object"))
        msg = attack(url + "/a")
        msg["body"] = "!!!not-base64!!!"
        hostile.append((msg, "body not base64"))
        msg = attack(url + "/a")
        msg["url"] = url.replace("127.0.0.1", "user:pass@127.0.0.1")
        hostile.append((msg, "URL with embedded credentials"))
        msg = attack(url + "/a")
        msg["method"] = None
        hostile.append((msg, "missing method"))
        msg = attack(url + "/a")
        del msg["url"]
        hostile.append((msg, "missing url"))
        msg = attack(url + "/a")
        msg["locations"] = "not-a-list"
        hostile.append((msg, "locations not a list"))

        for msg, why in hostile:
            out = broker.handle(msg)
            assert not out["ok"], why
            row = last_receipt(state)
            assert row["decision"] == "DENY", why
            assert not row["credential_released"], why
        # Referee: nothing was dispatched by any malformed message.
        assert seen == []

        # Positive control: the approved request still works.
        assert broker.handle(attack(url + "/a"))["ok"]
        assert [r[:3] for r in seen] == [("POST", "/a", b"hello")]
    finally:
        broker.close()
