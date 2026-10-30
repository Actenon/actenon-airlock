"""A rerun may send the same prompt; a consequence stays owned across runs."""

import httpx
from test_model_endpoints import message
from test_model_timeouts import configure

from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker


def _completion(request):
    return httpx.Response(
        200,
        json={
            "model": "test-model",
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        },
    )


def _broker(state, provider):
    broker = ProtectedBroker(state, discover(state.root, env={}))
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    return broker


def test_rerunning_a_project_can_send_the_same_first_prompt(tmp_path):
    state = configure(tmp_path, 600)
    calls = []
    for _ in range(2):
        broker = _broker(state, lambda request: calls.append(request) or _completion(request))
        try:
            assert broker.handle(message())["ok"]
        finally:
            broker.close()
    assert len(calls) == 2


def test_unresolved_inference_still_holds_within_its_run(tmp_path):
    state = configure(tmp_path, 600)
    calls = []

    def lost(request):
        calls.append(request)
        raise httpx.ReadTimeout("response lost", request=request)

    broker = _broker(state, lost)
    try:
        assert not broker.handle(message())["ok"]
        assert not broker.handle(message())["ok"]
    finally:
        broker.close()
    assert len(calls) == 1
