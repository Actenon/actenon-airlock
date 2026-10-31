"""The agent inference contract: what crosses, and every route that must not."""

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from anthropic_fixture import (
    BETAS,
    ENDPOINT,
    MODEL,
    PRICES,
    USAGE,
    ScriptedProvider,
    reply_body,
    stream_reply,
    text,
    tool,
)

from actenon_airlock import contained_agent
from actenon_airlock.agent_inference import (
    MAX_OUTPUT_TOKENS,
    bounds_expanded,
    cost,
    reservation,
)
from actenon_airlock.agents import command, parse_prices, usd_to_micro
from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import authority_diff, discover
from actenon_airlock.model_constraints import validate_profile
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State
from actenon_airlock.workflow import status

SECRET = "sk-ant-supervisor-held-test-value"
ROOT = Path(__file__).resolve().parents[1]
REQUEST = {
    "model": MODEL,
    "max_tokens": 2048,
    "stream": True,
    "system": [
        {"type": "text", "text": "attribution"},
        {"type": "text", "text": "prompt", "cache_control": {"type": "ephemeral"}},
    ],
    "tools": [
        {"name": "Bash", "description": "Run", "input_schema": {"type": "object"}},
        {"name": "Read", "description": "Read", "input_schema": {"type": "object"}},
    ],
    "messages": [
        {"role": "user", "content": [{"type": "text", "text": "fix the bug"}]},
        {"role": "system", "content": "environment note"},
        {
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "", "signature": "c2ln"},
                {"type": "redacted_thinking", "data": "b3BhcXVl"},
                {"type": "text", "text": "Reading."},
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "a.py"}},
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "code", "is_error": False},
                {
                    "type": "tool_result",
                    "tool_use_id": "t2",
                    "content": [
                        {"type": "text", "text": "shot"},
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": "aW1n",
                            },
                        },
                    ],
                },
            ],
        },
    ],
    "metadata": {"user_id": '{"session_id":"abc"}'},
    "thinking": {"type": "adaptive"},
    "output_config": {"effort": "medium"},
}


def configure(root: Path) -> State:
    code = main(
        [
            "setup",
            "--path",
            str(root),
            "--agent",
            "claude-code",
            "--model",
            MODEL,
            "--approve",
            "--max-run-usd",
            "1",
            "--price-per-mtok",
            PRICES,
        ]  # fmt: skip
    )
    assert code == 0
    return State(root)


def broker_for(state, provider, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    broker = ProtectedBroker(state, discover(state.root), state.approved()["credential_bindings"])
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    return broker


def message(body=None, *, headers=None, **changes):
    if body is None:
        body = json.dumps({**REQUEST, **changes}).encode()
    return {
        "kind": "protected-http",
        "method": "POST",
        "url": ENDPOINT,
        "headers": {
            "Content-Type": "application/json",
            "anthropic-beta": ",".join(BETAS),
            **(headers or {}),
        },
        "body": base64.b64encode(body).decode(),
    }


@pytest.fixture
def project(tmp_path, monkeypatch):
    state = configure(tmp_path)
    brokers = []

    def build(provider):
        brokers.append(broker_for(state, provider, monkeypatch))
        return brokers[-1]

    yield state, build
    for broker in brokers:
        broker.close()


def rows(state):
    return [item["row"] for item in state.verify_receipts()["rows"]]


def test_an_agent_request_reaches_the_provider_byte_for_byte(project):
    state, build = project
    provider = ScriptedProvider([[text("done")]])
    # Key order and spacing matter: rewriting replayed history can read as editing it.
    raw = json.dumps(REQUEST, sort_keys=False, indent=1).encode()
    result = build(provider).handle(message(raw))
    assert result["ok"] and result["outcome"] == "COMMITTED"
    assert provider.requests[0].content == raw


def test_the_supervisor_credential_replaces_anything_the_agent_sends(project):
    state, build = project
    provider = ScriptedProvider([[text("done")]])
    forged = {"x-api-key": "agent", "Authorization": "Bearer agent", "api-key": "agent"}
    assert build(provider).handle(message(headers=forged))["ok"]
    sent = provider.requests[0].headers
    assert sent["x-api-key"] == SECRET and "authorization" not in sent
    assert sent["anthropic-version"] == "2023-06-01"
    assert sent["anthropic-beta"] == ",".join(BETAS)
    assert SECRET not in state.receipts_path.read_text()


def test_a_reply_holding_the_key_is_masked_before_the_agent_sees_it(project):
    _, build = project
    leak = reply_body([text(f"key is {SECRET}")])
    reply = httpx.Response(200, headers={"content-type": "text/event-stream"}, content=leak)
    result = build(lambda request: reply).handle(message())
    assert SECRET.encode() not in base64.b64decode(result["response"]["body"])


URL_SOURCE = {"type": "url", "url": "https://sink.example/?data=secret"}
FILE_SOURCE = {"type": "file", "file_id": "file_123"}


def user(*blocks):
    return [{"role": "user", "content": list(blocks)}]


REFUSED = {
    "web search": {"tools": [{"type": "web_search_20260209", "name": "web_search"}]},
    "web fetch": {"tools": [{"type": "web_fetch_20260209", "name": "web_fetch"}]},
    "code execution": {"tools": [{"type": "code_execution_20260521", "name": "code_execution"}]},
    "computer": {"tools": [{"type": "computer_toolset_20260801", "name": "computer"}]},
    "tool search": {"tools": [{"type": "tool_search_tool_regex_20251119", "name": "search"}]},
    "mcp toolset": {"tools": [{"type": "mcp_toolset", "mcp_server_name": "remote"}]},
    "tool caller field": {
        "tools": [{"name": "x", "input_schema": {}, "allowed_callers": ["code_execution"]}]
    },
    "remote mcp": {"mcp_servers": [{"type": "url", "url": "https://sink.example", "name": "s"}]},
    "server container": {"container": {"skills": []}},
    "server fallback": {"fallbacks": "default"},
    "server context edits": {"context_management": {"edits": [{"type": "compact_20260112"}]}},
    "speed tier": {"speed": "fast"},
    "unknown field": {"anything_else": True},
    "image url": {"messages": user({"type": "image", "source": URL_SOURCE})},
    "image file": {"messages": user({"type": "image", "source": FILE_SOURCE})},
    "document url": {"messages": user({"type": "document", "source": URL_SOURCE})},
    "document file": {"messages": user({"type": "document", "source": FILE_SOURCE})},
    "url inside a tool result": {
        "messages": user(
            {
                "type": "tool_result",
                "tool_use_id": "t",
                "content": [{"type": "image", "source": URL_SOURCE}],
            }
        )
    },
    "server tool replay": {
        "messages": [
            {
                "role": "assistant",
                "content": [{"type": "server_tool_use", "id": "s", "name": "web_fetch"}],
            }
        ]
    },
    "mcp replay": {
        "messages": [{"role": "assistant", "content": [{"type": "mcp_tool_use", "id": "m"}]}]
    },
    "user sent tool call": {"messages": user({"type": "tool_use", "id": "t", "name": "n"})},
    "extra block field": {"messages": user({"type": "text", "text": "x", "citations": []})},
    "extra message field": {"messages": [{"role": "user", "content": "x", "name": "y"}]},
    "unknown role": {"messages": [{"role": "tool", "content": "x"}]},
    "no messages": {"messages": []},
    "other model": {"model": "claude-unapproved"},
    "fallback model field": {"model": [MODEL]},
    "output over bound": {"max_tokens": 16001},
    "boolean output bound": {"max_tokens": True},
    "unsupported effort": {"output_config": {"effort": "extreme"}},
    "structured output": {"output_config": {"effort": "low", "format": {}}},
    "unsupported thinking": {"thinking": {"type": "enabled", "budget_tokens": 1024}},
    "unsupported cache": {
        "system": [{"type": "text", "text": "x", "cache_control": {"type": "other"}}]
    },
    "long metadata": {"metadata": {"user_id": "x" * 1025}},
    "extra metadata": {"metadata": {"user_id": "x", "url": "https://sink.example"}},
    "non-boolean stream": {"stream": "true"},
}


@pytest.mark.parametrize("change", REFUSED.values(), ids=REFUSED.keys())
def test_out_of_contract_requests_never_reach_the_provider(project, change):
    state, build = project
    provider = ScriptedProvider([[text("done")]])
    result = build(provider).handle(message(**change))
    assert not result["ok"]
    assert provider.requests == []
    row = rows(state)[-1]
    assert row["decision"] == "DENY"
    assert row["credential_released"] is False and row["execution_occurred"] is False


@pytest.mark.parametrize(
    "raw",
    [
        b'{"model":"a","model":"claude-test-model","max_tokens":1,"messages":[]}',
        b'{"model":"claude-test-model","max_tokens":1,"messages":[{"role":"user",'
        b'"content":"x","content":[{"type":"image","source":{"type":"url"}}]}]}',
        b'{"model":"claude-test-model","max_tokens":NaN,"messages":[]}',
        b'{"model":"claude-test-model","max_tokens":1,"metadata":{"user_id":Infinity}}',
        b'["not an object"]',
        b"not json",
        b"\xff\xfe{}",
        b"{" * 100,
    ],
    ids=["duplicate", "nested duplicate", "nan", "infinity", "array", "text", "bom", "deep"],
)
def test_requests_a_parser_could_read_two_ways_are_refused(project, raw):
    _, build = project
    provider = ScriptedProvider([[text("done")]])
    assert not build(provider).handle(message(raw))["ok"]
    assert provider.requests == []


def test_an_input_over_its_signed_bound_is_refused(project):
    _, build = project
    provider = ScriptedProvider([[text("done")]])
    huge = [{"role": "user", "content": "x" * (2 * 1024 * 1024)}]
    assert not build(provider).handle(message(messages=huge))["ok"]
    assert provider.requests == []


@pytest.mark.parametrize(
    "headers",
    [
        {"anthropic-beta": "claude-code-20250219,mcp-client-2025-11-20"},
        {"anthropic-beta": "oauth-2025-04-20"},
        {"anthropic-beta": "files-api-2025-04-14"},
        {"anthropic-version": "2099-01-01"},
        {"Content-Type": "text/plain"},
        {"x-app": "cli"},
        {"anthropic-dangerous-direct-browser-access": "true"},
        {"idempotency-key": "fresh"},
        {"anthropic-workspace-id": "other"},
    ],
    ids=lambda value: next(iter(value)),
)
def test_headers_outside_the_contract_are_refused(project, headers):
    _, build = project
    provider = ScriptedProvider([[text("done")]])
    assert not build(provider).handle(message(headers=headers))["ok"]
    assert provider.requests == []


def test_a_model_tool_call_is_returned_as_data_and_grants_nothing(project):
    state, build = project
    consequence = tool(
        "t1", "github_create", url="https://api.github.com/repos/a/b/contents/x", content="y"
    )
    provider = ScriptedProvider([[consequence]])
    result = build(provider).handle(message())
    assert result["ok"] and result["outcome"] == "COMMITTED"
    assert len(provider.requests) == 1
    actions = {row["action"] for row in rows(state)}
    assert actions == {"http.post"}
    assert {row["target"] for row in rows(state)} == {ENDPOINT}


def test_only_a_reviewed_consequence_path_reaches_github(project):
    _, build = project
    provider = ScriptedProvider([[text("done")]])
    github = {**message(), "url": "https://api.github.com/repos/a/b/contents/x", "method": "PUT"}
    assert not build(provider).handle(github)["ok"]
    assert provider.requests == []


def replaced(old: bytes, new: bytes) -> bytes:
    body = reply_body([text("answer")])
    assert old in body
    return body.replace(old, new)


UNCONFIRMED = {
    "cut before the end": reply_body([text("answer")]).split(b"event: message_delta")[0],
    "no stop event": reply_body([text("answer")]).split(b"event: message_stop")[0],
    "other model": reply_body([text("answer")], model="claude-other"),
    "stream error": replaced(b"event: message_stop", b'event: error\ndata: {"type":"error"}\n\nx:'),
    "server tool block": replaced(b'"type":"text","text":""', b'"type":"server_tool_use"'),
    "mcp block": replaced(b'"type":"text","text":""', b'"type":"mcp_tool_use"'),
    "pause": reply_body([text("answer")], stop_reason="pause_turn"),
    "second start": replaced(
        b"event: ping\n", b'event: message_start\ndata: {"type":"message_start"}\n\nevent: ping\n'
    ),
    "wrong index": replaced(b'"index":0,"delta"', b'"index":3,"delta"'),
    "unknown event": replaced(b"event: ping", b"event: surprise"),
    "negative usage": replaced(b'"output_tokens":20', b'"output_tokens":-1'),
    "server tool usage": replaced(
        b'"output_tokens":20', b'"output_tokens":20,"server_tool_use":{"web_fetch_requests":1}'
    ),
    "not a stream": b"<html>gateway error</html>",
}


@pytest.mark.parametrize("body", UNCONFIRMED.values(), ids=UNCONFIRMED.keys())
def test_a_reply_outside_the_contract_confirms_nothing_and_holds_its_retry(project, body):
    _, build = project
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body)

    broker = build(provider)
    assert broker.handle(message())["outcome"] == "AMBIGUOUS"
    assert not broker.handle(message())["ok"]
    assert len(calls) == 1


def test_a_non_streaming_answer_can_be_confirmed(project):
    _, build = project
    reply = httpx.Response(
        200,
        json={
            "model": MODEL,
            "role": "assistant",
            "stop_reason": "tool_use",
            "content": [tool("t", "Bash", command="ls")],
            "usage": {"input_tokens": 3, "output_tokens": 4},
        },
    )
    assert build(lambda request: reply).handle(message(stream=False))["outcome"] == "COMMITTED"


@pytest.mark.parametrize("stop_reason", ["end_turn", "max_tokens", "tool_use", "refusal"])
def test_a_complete_stream_is_confirmed_whatever_stopped_it(project, stop_reason):
    _, build = project
    reply = stream_reply([text("answer")], stop_reason=stop_reason)
    assert build(lambda request: reply).handle(message())["outcome"] == "COMMITTED"


def test_identical_calls_under_the_contract_stay_separate(project):
    state, build = project
    provider = ScriptedProvider([[text("one")], [text("two")]])
    broker = build(provider)
    results = [broker.handle(message()) for _ in range(2)]
    assert all(result["outcome"] == "COMMITTED" for result in results)
    assert results[0]["effect_id"] != results[1]["effect_id"]
    assert status(state)["inference"]["confirmed"] == 2


def test_usage_becomes_a_receipted_estimate_from_signed_prices(project):
    state, build = project
    reply = reply_body([text("answer")], output_tokens=1000)
    reply = reply.replace(b'"cache_read_input_tokens":0', b'"cache_read_input_tokens":5000')
    provider = lambda request: httpx.Response(  # noqa: E731
        200, headers={"content-type": "text/event-stream"}, content=reply
    )
    assert build(provider).handle(message())["ok"]
    row = next(r for r in rows(state) if r.get("stage") == "response-received")
    assert row["inference_usage"]["cache_read_input_tokens"] == 5000
    # 100 input at $2, 5000 cache reads at $0.20 and 1000 output at $10 per million.
    assert row["inference_cost_microusd"] == 200 + 1000 + 10000
    assert status(state)["model_spend"]["estimated_microusd"] == 11200


def spend_bound(state, usd):
    approved = state.approved()
    profile = {**approved["protected_model"], "max_run_microusd": usd_to_micro(usd)}
    state.approve({**approved, "protected_model": profile})


def test_the_spend_bound_refuses_before_a_byte_leaves(project):
    state, build = project
    spend_bound(state, "0.03")
    provider = ScriptedProvider([[text("one")], [text("two")]])
    broker = build(provider)
    # Each reservation exceeds half the bound, so only the settled usage allows a second.
    assert broker.handle(message())["ok"]
    assert broker.handle(message())["ok"]
    assert len(provider.requests) == 2
    spend_bound(state, "0.0001")
    refused = build(provider).handle(message())
    assert not refused["ok"] and refused["reason"] == "Model spend bound reached for this run"
    assert len(provider.requests) == 2


def test_a_lost_reply_keeps_its_reservation_against_the_bound(project):
    state, build = project
    spend_bound(state, "0.03")
    calls = []

    def lost(request):
        calls.append(request)
        raise httpx.ReadTimeout("lost", request=request)

    broker = build(lost)
    assert not broker.handle(message())["ok"]
    reserved = broker.inference_spent
    assert reserved > 15_000
    different = message(max_tokens=2047)
    refused = broker.handle(different)
    assert not refused["ok"] and refused["reason"] == "Model spend bound reached for this run"
    assert len(calls) == 1
    row = next(r for r in rows(state) if r.get("stage") == "execution-error")
    assert row["inference_cost_microusd"] == reserved


@pytest.mark.parametrize(("code", "kind"), [(429, "rate_limit_error"), (529, "overloaded_error")])
def test_an_explicit_provider_refusal_lets_the_retry_be_a_new_call(project, code, kind):
    state, build = project
    declined = httpx.Response(code, json={"type": "error", "error": {"type": kind}})
    provider = ScriptedProvider([declined, [text("answer")]])
    broker = build(provider)
    first = broker.handle(message())
    assert first["ok"] and first["outcome"] == "AMBIGUOUS"
    assert broker.inference_spent == 0
    second = broker.handle(message())
    assert second["outcome"] == "COMMITTED"
    assert first["effect_id"] != second["effect_id"]
    assert status(state)["model_spend"]["declined_calls"] == 1
    # The refusal said nothing provable about billing, so its effect stays unconfirmed.
    assert first["effect_id"] in status(state)["unresolved_effects"]


@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(500, json={"type": "error", "error": {"type": "api_error"}}),
        httpx.Response(503, text="unavailable"),
        httpx.Response(429, text="not the provider's envelope"),
        httpx.Response(429, json={"type": "error", "error": {"type": "api_error"}}),
        httpx.Response(529, json={"error": "overloaded"}),
    ],
    ids=["500", "503", "429 unframed", "429 wrong type", "529 unframed"],
)
def test_any_other_failure_stays_uncertain_and_holds(project, reply):
    state, build = project
    calls = []
    broker = build(lambda request: calls.append(request) or reply)
    assert broker.handle(message())["outcome"] == "AMBIGUOUS"
    assert not broker.handle(message())["ok"]
    assert len(calls) == 1
    assert status(state)["model_spend"]["declined_calls"] == 0


def test_a_trickled_reply_is_stopped_by_its_overall_deadline(project):
    state, build = project
    calls = []
    provider = lambda request: calls.append(request) or stream_reply([text("slow")])  # noqa: E731
    broker = build(provider)
    broker.http_deadline = lambda url: time.monotonic() - 1
    result = broker.handle(message())
    assert not result["ok"]
    assert not broker.handle(message())["ok"]
    assert len(calls) == 1


def test_a_stopped_run_refuses_the_agent_contract_too(project):
    state, build = project
    provider = ScriptedProvider([[text("done")]])
    broker = build(provider)
    state.set_emergency_stop("test")
    assert not broker.handle(message())["ok"]
    assert provider.requests == []


def profile(**changes):
    base = {
        "provider": "anthropic",
        "models": [MODEL],
        "max_output_tokens": 16000,
        "contract": "anthropic-agent/v1",
        "max_input_bytes": 1024,
        "anthropic_betas": ["claude-code-20250219"],
        "price_microusd_per_mtok": parse_prices(PRICES),
        "max_run_microusd": 1_000_000,
    }
    return {**base, **changes}


@pytest.mark.parametrize(
    "changes",
    [
        {"contract": "something-else"},
        {"provider": "openai"},
        {"max_output_tokens": MAX_OUTPUT_TOKENS + 1},
        {"max_output_tokens": True},
        {"max_input_bytes": 0},
        {"max_input_bytes": 9 * 1024 * 1024},
        {"anthropic_betas": "claude-code-20250219"},
        {"anthropic_betas": ["*"]},
        {"anthropic_betas": ["same", "same"]},
        {"price_microusd_per_mtok": {"input": 1}},
        {"price_microusd_per_mtok": {**parse_prices(PRICES), "output": -1}},
        {"max_run_microusd": 0},
        {"models": ["*"]},
    ],
)
def test_invalid_agent_bounds_cannot_be_signed(changes):
    with pytest.raises(AirlockError):
        validate_profile(profile(**changes))


def test_contract_fields_mean_nothing_on_a_text_profile():
    text_profile = {"provider": "anthropic", "models": [MODEL], "max_output_tokens": 256}
    with pytest.raises(AirlockError, match="Unknown model constraint"):
        validate_profile({**text_profile, "max_run_microusd": 1})


def test_a_text_profile_keeps_its_own_bound():
    with pytest.raises(AirlockError):
        validate_profile({"provider": "anthropic", "models": [MODEL], "max_output_tokens": 5000})


@pytest.mark.parametrize(
    "changes",
    [
        {"contract": "anthropic-agent/v2"},
        {"anthropic_betas": ["claude-code-20250219", "mcp-client-2025-11-20"]},
        {"max_input_bytes": 2048},
        {"max_run_microusd": 2_000_000},
        {"price_microusd_per_mtok": {**parse_prices(PRICES), "output": 1}},
    ],
)
def test_loosening_a_signed_bound_needs_a_fresh_review(changes):
    before = {"powers": [], "protected_model": profile()}
    after = {"powers": [], "protected_model": profile(**changes)}
    assert authority_diff(before, after)["model_constraints"]["expanded"]


def test_moving_from_text_to_the_agent_contract_needs_a_fresh_review():
    text_profile = {"provider": "anthropic", "models": [MODEL], "max_output_tokens": 16000}
    diff = authority_diff(
        {"powers": [], "protected_model": text_profile},
        {"powers": [], "protected_model": profile()},
    )
    assert diff["model_constraints"]["expanded"]


def test_tightening_a_signed_bound_needs_no_review():
    narrower = profile(anthropic_betas=[], max_input_bytes=512, max_run_microusd=1)
    assert not bounds_expanded(narrower, profile())


def test_cost_rounds_up_and_a_reservation_exceeds_ordinary_use():
    prices = parse_prices(PRICES)
    assert cost({"output_tokens": 1}, prices) == 10
    assert cost({"cache_read_input_tokens": 1}, prices) == 1
    usage = {"input_tokens": 400, **{k: v for k, v in USAGE.items() if k != "input_tokens"}}
    assert reservation(4000, 2048, prices) > cost({**usage, "output_tokens": 2048}, prices)


@pytest.mark.parametrize("value", ["abc", "-1", "0.0000001", "NaN", ""])
def test_money_must_be_a_whole_positive_number_of_micro_usd(value):
    with pytest.raises(AirlockError):
        usd_to_micro(value)


def test_prices_need_every_token_class():
    with pytest.raises(AirlockError):
        parse_prices("2,2.5,0.2")
    assert parse_prices(PRICES) == {
        "input": 2_000_000,
        "cache_write": 2_500_000,
        "cache_read": 200_000,
        "output": 10_000_000,
    }


def test_setup_refuses_to_guess_prices_or_a_spend_bound(tmp_path, capsys):
    arguments = ["setup", "--path", str(tmp_path), "--agent", "claude-code", "--model", MODEL]
    assert main(arguments) == 2
    assert "--max-run-usd" in capsys.readouterr().err
    assert not (tmp_path / "airlock_agent.py").exists()


def test_review_shows_every_bound_and_activates_nothing(tmp_path, capsys):
    arguments = ["setup", "--path", str(tmp_path), "--agent", "claude-code", "--model", MODEL]
    assert main([*arguments, "--max-run-usd", "1", "--price-per-mtok", PRICES]) == 0
    output = capsys.readouterr().out
    assert "Review these powers" in output
    for bound in ("max_run_microusd", "price_microusd_per_mtok", "anthropic_betas", "contract"):
        assert bound in output
    assert not (tmp_path / ".airlock" / "approved.json").exists()


def test_a_subscription_token_is_refused_before_any_container_starts(tmp_path, capsys, monkeypatch):
    configure(tmp_path)
    (tmp_path / "ISSUE.md").write_text("task\n")
    capsys.readouterr()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-oat01-test")
    code = main(["work", "--path", str(tmp_path), "--message-file", "ISSUE.md"])
    assert code == 2
    assert "subscription" in capsys.readouterr().err
    assert not (tmp_path / ".airlock/local/runs").exists()


def test_the_launch_command_holds_no_secret_and_pins_every_model_alias():
    arguments = command(
        "claude-code", MODEL, "ISSUE.md", "pytest", max_output_tokens=16000, budget_usd="1"
    )
    joined = " ".join(arguments)
    assert "API_KEY" not in joined and "TOKEN=" not in joined and "OAUTH" not in joined
    assert f"--model {MODEL}" in joined
    for alias in ("OPUS", "SONNET", "HAIKU"):
        assert f"ANTHROPIC_DEFAULT_{alias}_MODEL={MODEL}" in arguments
    assert "--tools" in arguments
    assert "WebFetch" not in joined and "WebSearch" not in joined


def test_the_frozen_v2_aider_command_is_unchanged():
    frozen = json.loads((ROOT / "release/acceptance-v2/config.json").read_text())
    assert (
        command("aider", frozen["model"], "ISSUE.md", "python -m pytest -q")
        == (frozen["agent_command"])
    )


class RelayFixture:
    def __init__(self, monkeypatch, reply):
        self.sent = []

        def rpc(value):
            self.sent.append(value)
            return reply

        monkeypatch.setattr(contained_agent, "rpc", rpc)
        monkeypatch.setattr(
            contained_agent, "MODEL_TARGETS", {"/v1/messages": ENDPOINT}, raising=True
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), contained_agent.Relay)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def post(self, path, headers=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.server.server_port}{path}",
            b"{}",
            {"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()


def ok_reply(headers):
    return {
        "ok": True,
        "response": {
            "status": 200,
            "headers": headers,
            "body": base64.b64encode(b"data").decode(),
        },
    }


def test_relay_routes_the_clients_beta_path_to_the_one_exact_target(monkeypatch):
    relay = RelayFixture(monkeypatch, ok_reply({"content-type": "text/event-stream"}))
    status_code, headers, body = relay.post("/v1/messages?beta=true", {"anthropic-beta": "a"})
    relay.server.shutdown()
    assert status_code == 200 and body == b"data"
    assert headers["Content-Type"] == "text/event-stream"
    assert relay.sent[0]["url"] == ENDPOINT
    assert relay.sent[0]["headers"]["anthropic-beta"] == "a"


def test_relay_passes_only_retry_guidance_from_a_reply(monkeypatch):
    upstream = {"retry-after": "7", "x-should-retry": "true", "set-cookie": "no", "x-other": "no"}
    relay = RelayFixture(monkeypatch, ok_reply(upstream))
    _, headers, _ = relay.post("/v1/messages")
    relay.server.shutdown()
    lowered = {key.lower(): value for key, value in headers.items()}
    assert lowered["retry-after"] == "7" and lowered["x-should-retry"] == "true"
    assert "set-cookie" not in lowered and "x-other" not in lowered


def test_relay_reports_a_refusal_in_the_clients_own_error_shape(monkeypatch):
    relay = RelayFixture(monkeypatch, {"ok": False, "reason": "outside the contract"})
    status_code, _, body = relay.post("/v1/messages")
    relay.server.shutdown()
    assert status_code == 403
    assert json.loads(body)["error"] == {
        "type": "permission_error",
        "message": "outside the contract",
    }


def test_relay_answers_optional_token_counting_without_a_refused_effect(monkeypatch):
    relay = RelayFixture(monkeypatch, {"ok": False, "reason": "unused"})
    status_code, _, _ = relay.post("/v1/messages/count_tokens?beta=true")
    relay.server.shutdown()
    assert status_code == 404 and relay.sent == []


def test_relay_treats_other_query_strings_as_unknown_paths(monkeypatch):
    relay = RelayFixture(monkeypatch, {"ok": False, "reason": "refused"})
    relay.post("/v1/messages?target=elsewhere")
    relay.server.shutdown()
    assert relay.sent[0]["url"] != ENDPOINT
