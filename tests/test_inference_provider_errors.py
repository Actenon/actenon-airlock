"""Failed provider replies: safe signed status evidence, sanitized agent replies, held money.

Reproduces the V4.4 live failure: HTTP 401 whose message echoed a masked
credential. The contained agent must receive only a locally generated error;
the signed observation must say what happened in fixed vocabulary; and the
reservation must stay held, because a failed reply proves nothing about billing.
"""

import base64
import json

import httpx
import pytest
import test_agent_inference as anthropic
from responses_fixture import ScriptedProvider, text
from test_responses_inference import SECRET, configure, message

from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.workflow import status


def errors():
    from actenon_airlock import provider_errors

    return provider_errors


FAKE = "sk-proj-SYNTHETICfakeKEYvalue0123456789abcdefSECRETtail"
MASKED = SECRET[:8] + "*" * 20 + SECRET[-4:]
FRAGMENTS = (SECRET, SECRET[:8], SECRET[-4:], FAKE, FAKE[:8], FAKE[-4:], "****", "secret")


def openai_error(code, message="details", kind="invalid_request_error"):
    return {"error": {"message": message, "type": kind, "param": None, "code": code}}


CASES = {
    "401-full-key": (401, openai_error("invalid_api_key", f"Incorrect API key provided: {SECRET}")),
    "401-masked-key": (401, openai_error("invalid_api_key", f"Incorrect API key: {MASKED}.")),
    "401-other-key": (401, openai_error("invalid_api_key", f"Incorrect API key: {FAKE}")),
    "401-misleading-quota-code": (401, openai_error("insufficient_quota")),
    "403-region": (403, openai_error("unsupported_country_region_territory", "secret region")),
    "429-misleading-auth-code": (429, openai_error("invalid_api_key", FAKE)),
    "500-server": (500, openai_error("server_error", f"trace {FAKE}", "server_error")),
    "503-text": (503, f"upstream proxy said {FAKE}".encode()),
    "502-empty": (502, b""),
    "400-malformed": (400, b'{"error": {"message": "' + FAKE.encode()),
    "400-duplicate-keys": (
        400,
        b'{"error":{"code":"invalid_api_key"},"error":{"code":"' + FAKE.encode() + b'"}}',
    ),
    "400-non-object": (400, b'["' + FAKE.encode() + b'"]'),
    "401-secret-code": (401, openai_error(FAKE)),
    "401-code-not-string": (401, openai_error({"nested": FAKE})),
    "401-oversized": (401, openai_error("invalid_api_key", "x" * 200_000 + FAKE)),
}
EXPECTED = {
    # (provider_error_code, provider_error_body)
    "401-full-key": ("invalid_api_key", "json"),
    "401-masked-key": ("invalid_api_key", "json"),
    "401-other-key": ("invalid_api_key", "json"),
    "401-misleading-quota-code": ("insufficient_quota", "json"),
    "403-region": ("unsupported_country_region_territory", "json"),
    "429-misleading-auth-code": ("invalid_api_key", "json"),
    "500-server": ("server_error", "json"),
    "503-text": (None, "malformed"),
    "502-empty": (None, "empty"),
    "400-malformed": (None, "malformed"),
    "400-duplicate-keys": (None, "malformed"),
    "400-non-object": (None, "unexpected-shape"),
    "401-secret-code": ("unrecognised", "json"),
    "401-code-not-string": ("invalid", "json"),
    "401-oversized": (None, "oversized"),
}

SECRET_HEADERS = [
    ("set-cookie", f"session={FAKE}"),
    ("set-cookie", f"other={SECRET}"),
    ("x-request-id", "req_one"),
    ("x-request-id", "req_two"),
    ("openai-organization", "org-secret-tenant"),
    ("www-authenticate", f"Bearer realm={MASKED}"),
    ("retry-after", "1"),
]


def response(status, body):
    content = json.dumps(body).encode() if isinstance(body, dict) else body
    return httpx.Response(
        status, headers=[("content-type", "application/json"), *SECRET_HEADERS], content=content
    )


@pytest.fixture
def broker(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path)
    provider = ScriptedProvider([[text("ok")]])
    subject = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(provider))
    yield state, subject, provider
    subject.close()


def received(result):
    return base64.b64decode(result["response"]["body"], validate=True)


def assert_clean(blob: bytes):
    lowered = blob.lower()
    for fragment in FRAGMENTS:
        assert fragment.lower().encode() not in lowered, fragment


@pytest.mark.parametrize("case", CASES)
def test_failed_reply_is_sanitized_signed_and_held(broker, case):
    state, subject, provider = broker
    code, body = CASES[case]
    provider.steps.insert(0, response(code, body))
    result = subject.handle(message())
    assert result["ok"] and result["outcome"] == "AMBIGUOUS"

    # The agent sees the real status and a fixed local error, nothing provider-supplied.
    relayed = result["response"]
    assert relayed["status"] == code
    assert relayed["headers"] == {"content-type": "application/json"}
    assert_clean(received(result))
    assert_clean(json.dumps(relayed).encode())
    expected_code, kind = EXPECTED[case]

    # The signed observation carries the cause in fixed vocabulary only.
    row = next(r["row"] for r in state.verify_receipts()["rows"] if r["row"].get("outcome"))
    observation = row["inference_observation"]
    assert observation["rejection_reason"] == "http-status"
    assert observation["http_status"] == code
    assert observation.get("provider_error_code") == expected_code
    assert observation["provider_error_body"] == kind
    assert_clean(state.receipts_path.read_bytes())
    assert state.verify_receipts()["ok"]
    agent_code = expected_code if expected_code in errors().PROVIDER_ERROR_CODES else None
    assert json.loads(received(result)) == errors().sanitized_body(code, agent_code, "openai")


@pytest.mark.parametrize("case", [c for c in CASES if not c.startswith("429")])
def test_failed_reply_keeps_its_reservation_and_refuses_the_retry(broker, case):
    state, subject, provider = broker
    provider.steps.insert(0, response(*CASES[case]))
    first = subject.handle(message())
    held = subject.inference_spent
    assert first["outcome"] == "AMBIGUOUS" and held > 0
    assert not subject.handle(message())["ok"]  # identical retry stays refused
    assert subject.inference_spent == held
    assert len(provider.requests) == 1
    assert status(state)["model_spend"]["declined_calls"] == 0
    assert first["effect_id"] in status(state)["unresolved_effects"]


def test_401_is_never_treated_as_a_declined_or_zero_cost_reply(broker):
    state, subject, provider = broker
    provider.steps.insert(0, response(*CASES["401-misleading-quota-code"]))
    assert subject.handle(message())["outcome"] == "AMBIGUOUS"
    assert subject.inference_spent > 0
    row = next(r["row"] for r in state.verify_receipts()["rows"] if r["row"].get("outcome"))
    assert "inference_declined" not in row and "inference_usage" not in row


@pytest.mark.parametrize("code", ["rate_limit_exceeded", "insufficient_quota"])
def test_documented_429_declines_keep_their_existing_accounting_and_are_sanitized(broker, code):
    state, subject, provider = broker
    provider.steps.insert(0, response(429, openai_error(code, f"limit {FAKE}")))
    first = subject.handle(message())
    assert first["outcome"] == "AMBIGUOUS" and subject.inference_spent == 0
    assert first["response"]["status"] == 429
    assert_clean(json.dumps(first["response"]).encode())
    assert json.loads(received(first)) == errors().sanitized_body(429, code, "openai")
    assert subject.handle(message())["outcome"] == "COMMITTED"
    assert status(state)["model_spend"]["declined_calls"] == 1


def test_successful_replies_are_not_rewritten(broker):
    _, subject, provider = broker
    result = subject.handle(message())
    assert result["outcome"] == "COMMITTED" and result["response"]["status"] == 200
    assert b"response.completed" in received(result)


def test_anthropic_contract_failure_is_sanitized_and_signed(tmp_path, monkeypatch):
    state = anthropic.configure(tmp_path)
    leak = {
        "type": "error",
        "error": {"type": "authentication_error", "message": f"invalid x-api-key {FAKE}"},
    }
    calls = []
    subject = anthropic.broker_for(
        state, lambda r: calls.append(r) or response(401, leak), monkeypatch
    )
    try:
        result = subject.handle(anthropic.message())
        assert result["outcome"] == "AMBIGUOUS" and result["response"]["status"] == 401
        assert result["response"]["headers"] == {"content-type": "application/json"}
        assert_clean(json.dumps(result["response"]).encode())
        assert json.loads(received(result)) == errors().sanitized_body(
            401, "authentication_error", "anthropic"
        )
        rows = [r["row"] for r in state.verify_receipts()["rows"]]
        observation = next(r for r in rows if r.get("outcome"))["inference_observation"]
        assert observation["http_status"] == 401
        assert observation["provider_error_type"] == "authentication_error"
        assert_clean(state.receipts_path.read_bytes())
        assert not subject.handle(anthropic.message())["ok"] and len(calls) == 1
    finally:
        subject.close()


def test_status_diagnostic_is_bounded_and_fixed_vocabulary():
    deep = b'{"error":' * 5000 + b"0" + b"}" * 5000
    assert errors().status_diagnostic(401, deep)["provider_error_body"] == "malformed"
    for status_code in (99, 600, True, "401", None):
        assert errors().status_diagnostic(status_code, b"")["http_status"] == "invalid"
    report = errors().status_diagnostic(401, json.dumps(openai_error(FAKE, FAKE)).encode())
    assert FAKE not in json.dumps(report)
    assert set(report) <= {
        "http_status",
        "http_status_class",
        "provider_error_body",
        "provider_error_code",
        "provider_error_type",
    }
