"""Real engine reservations must survive lost HTTP responses and new runs."""

import json
import multiprocessing
from pathlib import Path

import httpx
from test_broker import message

from actenon_airlock.broker import Broker
from actenon_airlock.manifest import discover
from actenon_airlock.state import State


def _run_one_http(root, url, queue):
    state = State(Path(root))
    broker = Broker(state, discover(state.root))
    try:
        queue.put(broker.handle(message(url)))
    finally:
        broker.close()


def test_lost_response_retry_is_refused_after_restart_and_credential_rotation(project, monkeypatch):
    url = "https://api.github.com/repos/acme/support/issues"
    monkeypatch.setenv("GITHUB_TOKEN", "offline-secret")
    state = project(f'import requests\nrequests.post("{url}")\n')
    calls = []

    def provider(request):
        calls.append(request)
        raise httpx.ReadTimeout("effect may have committed", request=request)

    broker = Broker(state, discover(state.root))
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    first_message = message(url)
    first_message["headers"] = {"Authorization": "Bearer " + broker.markers["GITHUB_TOKEN"]}
    try:
        assert not broker.handle(first_message)["ok"]
        row = json.loads(state.receipts_path.read_text().splitlines()[-1])
        assert row["outcome"] == "AMBIGUOUS"
        assert row["execution_occurred"] is None
        assert row["kernel"]["reason_code"] == "OUTCOME_UNKNOWN"
        effect_id = row["effect_id"]
        assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"
    finally:
        broker.close()

    # A new grant, proof nonce, source digest and credential handle must not
    # create fresh ownership for this identical real-world HTTP request.
    (state.root / "main.py").write_text(
        f'import requests\nrequests.post("{url}")\n# source changed\n'
    )
    broker = Broker(state, discover(state.root))
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    retry = message(url)
    retry["headers"] = {"Authorization": "Bearer " + broker.markers["GITHUB_TOKEN"]}
    assert retry["headers"] != first_message["headers"]
    try:
        assert not broker.handle(retry)["ok"]
        refusal = json.loads(state.receipts_path.read_text().splitlines()[-1])
        assert refusal["decision"] == "DENY"
        assert not refusal["credential_released"] and not refusal["execution_occurred"]
        assert len(calls) == 1
        assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"
        assert state.verify_receipts()["ok"]
        assert "offline-secret" not in state.receipts_path.read_text()
    finally:
        broker.close()


def test_generic_http_response_is_not_proof_of_committed_consequence(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        response = broker.handle(message(url + "/a"))
        assert response["ok"] and response["response"]["status"] == 200
        row = json.loads(state.receipts_path.read_text().splitlines()[-1])
        assert row["outcome"] == "AMBIGUOUS"
        assert row["transport_completed"] is True
        assert row["execution_occurred"] is None
        assert row["stage"] == "response-received"
        assert not broker.handle(message(url + "/a"))["ok"]
        assert len(calls) == 1
    finally:
        broker.close()


def test_scan_read_only_http_operations_remain_repeatable(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.get("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        assert broker.handle(message(url + "/a", method="GET"))["ok"]
        assert broker.handle(message(url + "/a", method="GET"))["ok"]
        assert len(calls) == 2
    finally:
        broker.close()


def test_settlement_failure_keeps_dispatch_held_and_never_claims_non_execution(
    project, server, monkeypatch
):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))

    def unavailable(**_fields):
        raise OSError("private ledger diagnostic")

    monkeypatch.setattr(broker.store, "settle_effect", unavailable)
    try:
        assert not broker.handle(message(url + "/a"))["ok"]
        row = json.loads(state.receipts_path.read_text().splitlines()[-1])
        assert row["decision"] == "ALLOW"
        assert row["outcome"] == "AMBIGUOUS"
        assert row["execution_occurred"] is None
        assert broker.store.get_effect(row["effect_id"])[-1]["state"] == "DISPATCHING"
        assert not broker.handle(message(url + "/a"))["ok"]
        assert len(calls) == 1
        assert "private ledger diagnostic" not in state.receipts_path.read_text()
    finally:
        broker.close()


def test_distinct_http_bodies_do_not_collapse_into_one_effect(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        first = broker.handle(message(url + "/a"))
        second = broker.handle(message(url + "/a", body=b"different consequence"))
        assert first["ok"] and second["ok"]
        assert first["effect_id"] != second["effect_id"]
        assert len(calls) == 2
    finally:
        broker.close()


def test_mismatched_body_length_is_refused_before_dispatch(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    request = message(url + "/a")
    request["headers"] = {"Content-Length": "1"}
    try:
        assert not broker.handle(request)["ok"]
        assert calls == []
        row = json.loads(state.receipts_path.read_text().splitlines()[-1])
        assert row["decision"] == "DENY" and row["execution_occurred"] is False
    finally:
        broker.close()


def test_two_airlock_processes_share_one_consequential_dispatch(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(target=_run_one_http, args=(str(state.root), url + "/a", queue))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    try:
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            assert process.exitcode == 0
        assert sorted(result["ok"] for result in results) == [False, True]
        assert len(calls) == 1
        verification = state.verify_receipts()
        assert verification["ok"]
        denials = [
            item["row"] for item in verification["rows"] if item["row"]["decision"] == "DENY"
        ]
        assert len(denials) == 1
        assert denials[0]["execution_occurred"] is False
        assert denials[0]["credential_released"] is False
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)
        queue.close()


def test_literal_header_cannot_spoof_a_bound_credential_identity(project, monkeypatch):
    url = "https://api.github.com/repos/acme/support/issues"
    monkeypatch.setenv("GITHUB_TOKEN", "offline-secret")
    state = project(f'import requests\nrequests.post("{url}")\n')
    broker = Broker(state, discover(state.root))
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(lambda _q: httpx.Response(200, json={"ok": True}))
    )
    try:
        literal = message(url)
        literal["headers"] = {"Authorization": "Bearer airlock-bound-credential:GITHUB_TOKEN"}
        credential = message(url)
        credential["headers"] = {"Authorization": "Bearer " + broker.markers["GITHUB_TOKEN"]}
        first, second = broker.handle(literal), broker.handle(credential)
        assert first["ok"] and second["ok"]
        assert first["effect_id"] != second["effect_id"]
    finally:
        broker.close()
