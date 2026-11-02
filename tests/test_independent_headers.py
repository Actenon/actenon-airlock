"""Unknown provider headers fail closed; inference transport is host-selected."""

import httpx
import pytest
from test_broker import message
from test_protected import model_project, request

from actenon_airlock.broker import Broker
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker


@pytest.mark.parametrize(
    "headers",
    [
        {"Stripe-Account": "tenant-b"},
        {"OpenAI-Project": "project-b"},
        {"If-Match": "revision-b"},
        {"Idempotency-Key": "new-key"},
        {"X-HTTP-Method-Override": "DELETE"},
        {"Content-Encoding": "gzip"},
    ],
)
def test_unknown_consequence_headers_never_dispatch(project, server, headers):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        item = message(url + "/a")
        item["headers"] = headers
        assert not broker.handle(item)["ok"]
        assert calls == []
        assert broker.handle(message(url + "/a"))["ok"]
        assert len(calls) == 1
    finally:
        broker.close()


def test_content_type_cannot_reset_ambiguous_byte_ownership(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    try:
        item = message(url + "/a")
        item["headers"] = {"Content-Type": "application/json"}
        assert broker.handle(item)["ok"]
        item["headers"] = {"Content-Type": "application/json; charset=utf-8"}
        assert not broker.handle(item)["ok"]
        assert len(calls) == 1
    finally:
        broker.close()


def test_inference_method_override_never_reaches_provider(tmp_path):
    state = model_project(
        tmp_path,
        "from openai import OpenAI\nOpenAI().chat.completions.create(model='test-model', messages=[])\n",
    )
    broker = ProtectedBroker(state, discover(state.root))
    calls = []
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json={}))
    )
    try:
        item = request()
        item["headers"] = {"X-HTTP-Method-Override": "DELETE"}
        assert not broker.handle(item)["ok"]
        assert calls == []
    finally:
        broker.close()


def test_legacy_header_identity_cannot_silently_upgrade_and_redispatch(project, server):
    from actenon_airlock.common import AirlockError, digest

    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    broker._effect_headers = lambda headers: {"content-type": [{"literal": "application/json"}]}
    try:
        assert broker.handle(message(url + "/a"))["ok"]
        rows = state.verify_receipts()["rows"]
        assert rows[0]["row"]["intent"]["action"]["parameters"]["headers_effect_sha256"] != digest(
            {}
        )
    finally:
        broker.close()
    with pytest.raises(AirlockError, match="legacy header-dependent"):
        Broker(state, discover(state.root))
    assert len(calls) == 1


def test_legacy_database_without_journal_still_blocks_upgrade(project, server):
    from actenon_airlock.common import AirlockError

    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    broker = Broker(state, discover(state.root))
    broker._effect_headers = lambda headers: {"content-type": [{"literal": "application/json"}]}
    try:
        assert broker.handle(message(url + "/a"))["ok"]
    finally:
        broker.close()
    state.receipts_path.unlink()
    with pytest.raises(AirlockError, match="legacy header-dependent"):
        Broker(state, discover(state.root))
    assert len(calls) == 1
