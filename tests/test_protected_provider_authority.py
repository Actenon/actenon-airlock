"""Protected execution needs a reviewed consequence profile, not HTTP verb guesses."""

import base64
import json

import httpx
import pytest

from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State


@pytest.mark.parametrize(
    "method,url,body",
    [
        ("GET", "https://example.com/delete-everything", b""),
        ("HEAD", "https://example.com/start-job", b""),
        ("OPTIONS", "https://example.com/start-job", b""),
        (
            "PUT",
            "https://api.github.com/repos/acme/review/contents/result.patch",
            json.dumps(
                {"branch": "review", "message": "reviewed change", "content": "eA=="}
            ).encode(),
        ),
    ],
)
def test_scanned_http_power_alone_does_not_approve_protected_consequence(
    tmp_path, method, url, body
):
    # This is a capture-only executor, not a real destructive endpoint.
    (tmp_path / "agent.py").write_text(f"import requests\nrequests.{method.lower()}({url!r})\n")
    state = State(tmp_path)
    current = discover(tmp_path, env={})
    state.approve(current)
    calls = []
    broker = ProtectedBroker(state, current)
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: calls.append(request) or httpx.Response(200, json={"fixture": True})
        )
    )
    try:
        result = broker.handle(
            {
                "kind": "protected-http",
                "method": method,
                "url": url,
                "headers": {},
                "body": base64.b64encode(body).decode(),
            }
        )
        assert not result["ok"] and calls == [], {"result": result, "dispatches": len(calls)}
        journal = state.verify_receipts()
        assert journal["ok"]
        last = journal["rows"][-1]["row"]
        assert last["decision"] == "DENY"
        assert last["credential_released"] is False
        assert last["execution_occurred"] is False
    finally:
        broker.close()
