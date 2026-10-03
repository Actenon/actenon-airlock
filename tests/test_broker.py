import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from actenon.models import ActionIntent
from actenon_permit.model import Action, GrantStatus

from actenon_airlock.broker import Broker
from actenon_airlock.manifest import capability, discover, request_capability


def message(url, line=2, method="POST"):
    return {
        "kind": "http",
        "method": method,
        "url": url,
        "headers": {},
        "body": base64.b64encode(b"hello").decode(),
        "locations": [{"file": "main.py", "line": line, "col": 1}],
    }


def test_real_permit_kernel_allow_and_deny(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        assert broker.handle(message(url + "/a"))["ok"]
        assert not broker.handle(message(url + "/b"))["ok"]
        assert len(calls) == 1 and calls[0][0] == "/a"
        rows = [
            json.loads(line) for line in (state.local / "receipts.jsonl").read_text().splitlines()
        ]
        allow = next(r for r in rows if r.get("stage") == "executed")
        deny = rows[-1]
        assert allow["kernel"]["receipt"]["outcome"] == "executed"
        assert allow["execution_occurred"] is True
        assert deny["decision"] == "DENY"
        assert not deny["credential_released"] and not deny["execution_occurred"]
        proof = next(r["proof"] for r in rows if "proof" in r)
        assert proof["signature"]["algorithm"] == "EdDSA"
    finally:
        broker.close()


def test_empty_scope_is_explicit_deny_all(project, server):
    url, calls = server
    state = project("print('safe')\n")
    broker = Broker(state, discover(state.root))
    try:
        assert broker.grant.scopes.deny == ["*"]
        assert not broker.handle(message(url + "/a"))["ok"]
        assert not calls
    finally:
        broker.close()


def test_old_target_revoked_new_target_needs_approval(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    (state.root / "main.py").write_text(f'import requests\nrequests.post("{url}/b")\n')
    broker = Broker(state, discover(state.root))
    try:
        assert not broker.handle(message(url + "/a"))["ok"]
        assert not broker.handle(message(url + "/b"))["ok"]
        assert calls == []
    finally:
        broker.close()
    state.approve(discover(state.root))
    broker = Broker(state, discover(state.root))
    try:
        assert broker.handle(message(url + "/b"))["ok"]
        assert len(calls) == 1
    finally:
        broker.close()


def test_unresolved_runtime_request_uses_permit_deny(project, server):
    url, calls = server
    state = project(
        f'import requests\nrequests.post("{url}/a")\ndef f(url):\n requests.post(url)\nhandlers=[f]\n'
    )
    broker = Broker(state, discover(state.root))
    try:
        out = broker.handle(message(url + "/a", line=4))
        assert not out["ok"] and calls == []
        row = json.loads((state.local / "receipts.jsonl").read_text().splitlines()[-1])
        assert row["permit_decision"]["outcome"] == "DENY"
    finally:
        broker.close()


def test_revocation_denies_before_transport(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        assert broker.handle(message(url + "/a"))["ok"]
        assert broker.handle(message(url + "/a"))["ok"]
        broker.store.set_status(broker.grant.id, GrantStatus.REVOKED)
        out = broker.handle(message(url + "/a"))
        assert not out["ok"] and "revoked" in out["reason"]
        assert len(calls) == 2
    finally:
        broker.close()


def test_stored_grant_scope_tampering_is_refused(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        tampered = broker.store.get_grant(broker.grant.id)
        tampered.scopes.allow.append("*")
        broker.store.put_grant(tampered)
        out = broker.handle(message(url + "/a"))
        assert not out["ok"] and out["reason"] == "Signed Permit grant could not be verified"
        assert not calls
    finally:
        broker.close()


def test_source_mutation_during_run_refuses(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        (state.root / "main.py").write_text("# mutated\n")
        assert not broker.handle(message(url + "/a"))["ok"]
        assert not calls
    finally:
        broker.close()


def test_kernel_rejects_target_mutation_and_replay(project, server):
    url, _ = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    current = discover(state.root)
    broker = Broker(state, current)
    try:
        cap, _ = request_capability(
            current, "POST", url + "/a", [{"file": "main.py", "line": 2, "col": 1}]
        )
        action = Action(grant_id=broker.grant.id, type=cap, target=url + "/a", params={})
        _, intent, proof = broker.pdp.decide_and_mint_pccb(broker.grant, action)
        actual = intent.to_dict()
        actual["target"]["resource_id"] = url + "/b"
        mutated = ActionIntent.from_dict(actual)
        effects = []
        out = broker.edge.protect(mutated, proof, lambda: effects.append(1))
        assert not out.ok and effects == []
        good = broker.edge.protect(intent, proof, lambda: effects.append(1))
        assert good.ok and effects == [1]
        replay = broker.edge.protect(intent, proof, lambda: effects.append(2))
        assert not replay.ok and effects == [1]
    finally:
        broker.close()


def test_credentials_stay_parent_owned_and_origin_bound(project, monkeypatch):
    secret = "test-secret-do-not-log"
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    state = project(
        'import requests\nrequests.post("https://api.github.com/repos/acme/project/issues")\n'
    )
    broker = Broker(state, discover(state.root))
    observed = []

    def transport(req):
        observed.append(req.headers["Authorization"])
        return httpx.Response(201, json={"ok": True})

    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(transport), trust_env=False)
    try:
        marker = broker.child_environment()["GITHUB_TOKEN"]
        assert marker != secret and marker in broker.credentials
        msg = message("https://api.github.com/repos/acme/project/issues")
        msg["headers"] = {"Authorization": "Bearer " + marker}
        assert broker.handle(msg)["ok"]
        assert observed == ["Bearer " + secret]
        assert secret not in (state.local / "receipts.jsonl").read_text()
        msg["url"] = "https://attacker.example/a"
        assert not broker.handle(msg)["ok"]
        assert len(observed) == 1
    finally:
        broker.close()


def test_attenuation_cannot_change_target_scope(project):
    state = project('import requests\nrequests.post("https://example.com/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        other = capability(
            {
                "action": "http.post",
                "resource": "example.com/b",
                "transport": "https://example.com/b",
            }
        )
        with pytest.raises(ValueError, match="widen"):
            broker.grant.attenuate(scopes_allow=[other])
        child = broker.grant.attenuate(expires_at=datetime.now(UTC) + timedelta(minutes=1))
        assert child.scopes.allow == broker.grant.scopes.allow and child.verify()
    finally:
        broker.close()


def test_timeout_after_dispatch_keeps_allow_and_unknown_execution(project, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "offline-timeout-secret")
    url = "https://api.github.com/repos/acme/support/issues"
    state = project(f'import requests\nrequests.post("{url}")\n')
    broker = Broker(state, discover(state.root))
    observed = []

    def timeout(req):
        observed.append(req.headers["Authorization"])
        raise httpx.ReadTimeout("offline response timeout", request=req)

    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(timeout), trust_env=False)
    try:
        msg = message(url)
        msg["headers"] = {"Authorization": "Bearer " + broker.markers["GITHUB_TOKEN"]}
        result = broker.handle(msg)
        assert not result["ok"]
        row = json.loads((state.local / "receipts.jsonl").read_text().splitlines()[-1])
        assert row["decision"] == "ALLOW" and row["stage"] == "execution-error"
        assert row["execution_attempted"] and row["execution_occurred"] is None
        assert row["credential_released"] is True
        assert row["kernel"]["reason_code"] == "EXECUTION_FAILED"
        assert broker.denials == 0 and broker.execution_errors == 1
        assert observed == ["Bearer offline-timeout-secret"]
        assert "offline-timeout-secret" not in (state.local / "receipts.jsonl").read_text()
    finally:
        broker.close()
