import base64
import json

import httpx
import pytest

from actenon_airlock.cli import main
from actenon_airlock.manifest import authority_diff, discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State

ENDPOINT = "http://127.0.0.1:11434/v1/chat/completions"
PROFILE = {
    "provider": "openai",
    "endpoint": ENDPOINT,
    "models": ["test-model"],
    "max_output_tokens": 128,
}


def setup(root):
    (root / "main.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI(base_url='http://127.0.0.1:11434/v1')\n"
        "client.chat.completions.create(model='test-model', messages=[])\n"
    )
    state = State(root)
    state.approve({**discover(root, env={}), "protected_model": PROFILE})
    return state


def message(model="test-model", **body):
    return {
        "kind": "protected-http",
        "url": ENDPOINT,
        "method": "POST",
        "headers": {},
        "body": base64.b64encode(
            json.dumps(
                {"model": model, "messages": [{"role": "user", "content": "fix the code"}], **body}
            ).encode()
        ).decode(),
    }


@pytest.mark.parametrize("body", [{"model": "unapproved"}, {"max_tokens": 129}, {"tools": []}])
def test_custom_endpoint_cannot_bypass_signed_model_constraints(tmp_path, body):
    state = setup(tmp_path)
    broker = ProtectedBroker(state, discover(tmp_path, env={}))
    calls = []
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json={}))
    )
    try:
        assert not broker.handle(message(**body))["ok"]
        assert calls == []
        assert state.verify_receipts()["ok"]
        row = state.verify_receipts()["rows"][-1]["row"]
        assert row["decision"] == "DENY"
        assert row["execution_occurred"] is False and row["credential_released"] is False
    finally:
        broker.close()


def test_custom_model_endpoint_keeps_scan_target_proof_and_transport_identical(tmp_path):
    state = setup(tmp_path)
    current = discover(tmp_path, env={})
    assert current["powers"] == [
        {
            "action": "http.post",
            "resource": "127.0.0.1:11434/v1/chat/completions",
            "transport": ENDPOINT,
        }
    ]
    broker = ProtectedBroker(state, current)
    calls = []

    def provider(req):
        calls.append(req)
        return httpx.Response(
            200,
            json={
                "model": "test-model",
                "choices": [
                    {"finish_reason": "stop", "message": {"role": "assistant", "content": "fixed"}}
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 2},
            },
        )

    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    try:
        value = broker.handle(message())
        assert value["ok"], value
        assert str(calls[0].url) == ENDPOINT
        assert json.loads(calls[0].content)["max_tokens"] == 128
        rows = [item["row"] for item in state.verify_receipts()["rows"]]
        executed = rows[-1]
        assert executed["target"] == ENDPOINT
        assert executed["outcome"] == "COMMITTED" and executed["execution_occurred"] is True
        assert executed["credential_released"] is False
        assert not broker.handle(message())["ok"]
        assert len(calls) == 1
    finally:
        broker.close()


def test_endpoint_change_is_authority_expansion_even_with_identical_code_powers():
    before = {"powers": [], "protected_model": PROFILE}
    after = {
        "powers": [],
        "protected_model": {**PROFILE, "endpoint": "https://model.example/v1/chat/completions"},
    }
    result = authority_diff(before, after)
    assert result["model_constraints"]["expanded"]
    assert result["runtime_status"] == "BLOCKED UNTIL APPROVED"


def test_cli_reviews_and_signs_custom_endpoint_without_creating_source_authority(tmp_path):
    state = setup(tmp_path)
    assert (
        main(
            [
                "init",
                "--path",
                str(tmp_path),
                "--approve",
                "--model",
                "test-model",
                "--model-endpoint",
                ENDPOINT,
                "--model-max-tokens",
                "128",
            ]
        )
        == 0
    )
    assert state.approved()["protected_model"] == PROFILE
    assert state.approved()["powers"] == discover(tmp_path, env={})["powers"]


@pytest.mark.parametrize(
    "operation", ["chat.completions.create", "responses.create", "images.generate"]
)
def test_unreviewed_or_unsupported_native_sdk_endpoint_cannot_fall_through_to_http(
    tmp_path, operation
):
    (tmp_path / "main.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI(base_url='http://127.0.0.1:11434/v1')\n"
        f"client.{operation}(model='test-model')\n"
    )
    state = State(tmp_path)
    current = discover(tmp_path, env={})
    assert current["powers"]
    state.approve(current)  # HTTP power alone cannot imply reviewed model/server tools.
    broker = ProtectedBroker(state, current)
    calls = []
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(lambda req: calls.append(req)))
    try:
        value = {**message(), "url": current["powers"][0]["transport"]}
        assert not broker.handle(value)["ok"]
        assert calls == []
        assert state.verify_receipts()["ok"]
    finally:
        broker.close()


def test_endpoint_profile_does_not_create_a_missing_http_power(tmp_path):
    (tmp_path / "main.py").write_text("print('compute only')\n")
    assert (
        main(
            [
                "init",
                "--path",
                str(tmp_path),
                "--approve",
                "--model",
                "test-model",
                "--model-endpoint",
                ENDPOINT,
            ]
        )
        == 2
    )
    assert not (tmp_path / ".airlock" / "approved.json").exists()


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://model.example/v1/chat/completions",
        "http://localhost:11434/v1/chat/completions",
        ENDPOINT + "?forward=1",
    ],
)
def test_custom_endpoint_transport_does_not_widen_to_dns_or_query_routes(tmp_path, endpoint):
    state = setup(tmp_path)
    original = (state.path / "approved.json").read_bytes()
    assert (
        main(
            [
                "init",
                "--path",
                str(tmp_path),
                "--approve",
                "--model",
                "test-model",
                "--model-endpoint",
                endpoint,
            ]
        )
        == 2
    )
    assert (state.path / "approved.json").read_bytes() == original
