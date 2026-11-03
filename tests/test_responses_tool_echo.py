"""Independent echo compatibility and exact approved-definition boundary tests."""

import copy
import json

import httpx
import pytest
from responses_fixture import ScriptedProvider
from responses_tool_echo_fixture import EIGHT, custom, echo, function, stream
from test_responses_inference import (  # noqa: F401
    PROFILE,
    REQUEST,
    SECRET,
    broker,
    configure,
    message,
)
from test_responses_observation import wire

from actenon_airlock import responses_inference as contract
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.workflow import status


def observe(inventory, seq, streaming=True, **changes):
    request = {
        **REQUEST,
        "tools": inventory,
        "max_output_tokens": 16000,
        "stream": streaming,
        **changes,
    }
    # The fixture must itself pass the existing outbound validator.
    request = json.loads(contract.check_request(json.dumps(request).encode(), PROFILE))
    body = wire(seq) if streaming else json.dumps(seq[-1]["response"]).encode()
    return contract.observe(200, body, request)


INVENTORIES = [
    [],
    [function()],
    [custom()],
    [function(), custom()],
    EIGHT,
    [{"type": "namespace", "name": "functions", "description": "Local tools", "tools": EIGHT}],
]


@pytest.mark.parametrize("inventory", INVENTORIES)
@pytest.mark.parametrize("defaults", [False, True])
@pytest.mark.parametrize("streaming", [True, False])
def test_documented_echo_preserves_exact_approved_inventory(inventory, defaults, streaming):
    result = observe(inventory, stream(echo(inventory, defaults)), streaming)
    assert result.confirmed, result.diagnostics
    assert result.usage == {
        "input_tokens": 90,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 10,
        "output_tokens": 20,
    }


@pytest.mark.parametrize("inventory", [[function()], [custom()], EIGHT])
def test_broker_default_echo_settles_and_permits_budgeted_continuation(
    tmp_path, monkeypatch, inventory
):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path, "0.7")
    provider = ScriptedProvider([httpx.Response(200, content=wire(stream(echo(inventory))))] * 2)
    subject = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(provider))
    try:
        first = subject.handle(message(tools=inventory))
        assert first["outcome"] == "COMMITTED", first
        assert subject.inference_spent == 1055
        assert (
            subject.handle(message(tools=inventory, instructions="Continue"))["outcome"]
            == "COMMITTED"
        )
        assert subject.inference_spent == 2110
        assert len(provider.requests) == 2
        assert json.loads(provider.requests[0].content)["tools"] == inventory
        assert state.verify_receipts()["ok"] and status(state)["integrity_ok"]
    finally:
        subject.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("allowed_callers", None),
        ("allowed_callers", ["direct"]),
        ("defer_loading", None),
        ("defer_loading", False),
        ("async", False),
        ("output_schema", None),
    ],
)
def test_supported_echo_defaults_independently(field, value):
    original = [function()]
    returned = copy.deepcopy(original)
    returned[0][field] = value
    assert observe(original, stream(returned)).confirmed


def test_tool_order_is_not_call_identity_or_output_item_order():
    original = INVENTORIES[-1]
    returned = echo(original)
    returned[0]["tools"].reverse()
    assert observe(original, stream(returned)).confirmed
    assert observe(EIGHT, stream(list(reversed(echo(EIGHT))))).confirmed


def test_custom_unconstrained_text_default_and_empty_description():
    original = [{"type": "custom", "name": "apply_patch"}]
    returned = echo(original)
    returned[0].update(format={"type": "text"}, description="")
    assert observe(original, stream(returned)).confirmed
    returned[0]["description"] = None
    assert observe(original, stream(returned)).confirmed


@pytest.mark.parametrize("strict", [None, False, True])
def test_omitted_strict_may_resolve_only_without_schema_changes(strict):
    original = [function()]
    del original[0]["strict"]
    returned = echo(original)
    returned[0]["strict"] = strict
    assert observe(original, stream(returned)).confirmed


MUTATIONS = [
    ("allowed_callers", ["programmatic"], "caller-mode"),
    ("allowed_callers", ["direct", "programmatic"], "caller-mode"),
    ("allowed_callers", [], "caller-mode"),
    ("allowed_callers", ["direct", "direct"], "caller-mode"),
    ("allowed_callers", "direct", "field-type"),
    ("allowed_callers", [1], "field-type"),
    ("defer_loading", True, "deferred-loading"),
    ("defer_loading", 0, "field-type"),
    ("async", True, "async-execution"),
    ("async", None, "field-type"),
    ("async", 0, "field-type"),
    ("output_schema", {}, "output-schema"),
    ("output_schema", {"type": "object"}, "output-schema"),
    ("output_schema", "private", "field-type"),
    ("parameters", {"type": "object"}, "definition"),
    ("parameters", None, "field-type"),
    (
        "parameters",
        {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
            "additionalProperties": 0,
        },
        "definition",
    ),
    ("strict", True, "definition"),
    ("strict", None, "definition"),
    ("strict", 0, "field-type"),
    ("description", "changed-private-description", "definition"),
    ("description", [], "field-type"),
    ("name", "write_stdin", "identity"),
    ("name", 0, "field-type"),
    ("type", "custom", "unsupported-field"),
    ("type", "web_search", "unsupported-type"),
    ("type", "mcp", "unsupported-type"),
    ("type", "tool_search", "unsupported-type"),
    ("type", "programmatic_tool_calling", "unsupported-type"),
    ("type", "shell", "unsupported-type"),
    ("type", [], "field-type"),
    ("synthetic-secret-name", "synthetic-secret-value", "unsupported-field"),
]


@pytest.mark.parametrize("field,value,reason", MUTATIONS)
@pytest.mark.parametrize("position", [0, 1, -1])
def test_capability_changes_are_unconfirmed_at_every_snapshot(field, value, reason, position):
    seq = stream([function()])
    seq[position]["response"]["tools"][0][field] = value
    result = observe([function()], seq)
    assert not result.confirmed and result.usage is None
    assert result.diagnostics["rejection_reason"] == "response-tools"
    assert result.diagnostics["validation_stage"] == "response-tool-echo"
    assert result.diagnostics["tool_rejection_reason"] == reason
    if position == -1:
        assert not observe([function()], seq, False).confirmed


@pytest.mark.parametrize(
    "case",
    [
        "added",
        "removed",
        "duplicate",
        "same-count-duplicate",
        "type",
        "namespace",
        "namespace-extra",
        "nested-namespace",
    ],
)
def test_tool_identity_count_scope_and_uniqueness(case):
    original = [function(), custom()]
    returned = copy.deepcopy(original)
    if case == "added":
        returned.append(function("write_stdin"))
    elif case == "removed":
        returned.pop()
    elif case == "duplicate":
        returned.append(copy.deepcopy(returned[0]))
    elif case == "same-count-duplicate":
        returned[1] = copy.deepcopy(returned[0])
    elif case == "type":
        returned[0] = {"type": "custom", "name": "exec_command"}
    elif case == "namespace":
        returned = [{"type": "namespace", "name": "functions", "tools": returned}]
    else:
        original = copy.deepcopy(INVENTORIES[-1])
        returned = copy.deepcopy(original)
        if case == "namespace-extra":
            returned[0]["allowed_callers"] = ["direct"]
        else:
            returned[0]["tools"] = [copy.deepcopy(returned[0])]
    assert not observe(original, stream(returned)).confirmed


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        {"type": "text"},
        {"type": "grammar", "syntax": "regex", "definition": "patch"},
        {"type": "grammar", "syntax": "lark", "definition": "changed"},
        {**custom()["format"], "secret-field": "secret-value"},
    ],
)
def test_custom_format_never_changes(value):
    returned = [custom()]
    returned[0]["format"] = value
    assert not observe([custom()], stream(returned)).confirmed


def test_dictionary_key_order_is_equivalent_but_schema_arrays_are_not_rewritten():
    original = [function()]
    returned = echo(original)
    returned[0]["parameters"] = dict(reversed(list(original[0]["parameters"].items())))
    assert observe(original, stream(returned)).confirmed
    returned[0]["parameters"]["new-secret-property"] = None
    assert not observe(original, stream(returned)).confirmed


def test_omitted_echo_is_not_an_empty_or_null_inventory():
    seq = stream([])
    for e in seq:
        if "response" in e:
            del e["response"]["tools"]
    assert observe(EIGHT, seq).confirmed
    assert not observe(EIGHT, stream([])).confirmed
    assert not observe([], stream(None)).confirmed


def test_inline_additional_tools_are_not_lifted_into_the_top_level_echo():
    declaration = {"type": "additional_tools", "role": "developer", "tools": [custom()]}
    inp = [*REQUEST["input"], declaration]
    assert observe([function()], stream(echo([function()])), input=inp).confirmed
    assert not observe([function()], stream(echo([function(), custom()])), input=inp).confirmed


@pytest.mark.parametrize(
    "failure",
    [
        "partial",
        "incomplete",
        "usage-missing",
        "usage-invalid",
        "identity",
        "model",
        "output",
        "after-terminal",
    ],
)
def test_compatible_echo_never_substitutes_for_complete_valid_response(failure):
    seq = stream(echo(EIGHT))
    final = seq[-1]["response"]
    if failure == "partial":
        seq.pop()
    elif failure == "incomplete":
        seq[-1]["type"] = "response.incomplete"
        final["status"] = "incomplete"
    elif failure == "usage-missing":
        del final["usage"]
    elif failure == "usage-invalid":
        final["usage"]["total_tokens"] = 0
    elif failure in ("identity", "model"):
        final["id" if failure == "identity" else "model"] = "changed"
    elif failure == "output":
        final["output"] = []
    else:
        seq.append(copy.deepcopy(seq[-1]))
    assert not observe(EIGHT, seq).confirmed


@pytest.mark.parametrize("kind", ["function", "custom"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("allowed_callers", ["direct"]),
        ("defer_loading", False),
        ("async", False),
        ("output_schema", None),
    ],
)
def test_new_echo_fields_never_expand_outbound_authority(broker, kind, field, value):  # noqa: F811
    _, subject, provider = broker
    original = function() if kind == "function" else custom()
    original[field] = value
    with pytest.raises(AirlockError):
        contract.check_request(json.dumps({**REQUEST, "tools": [original]}).encode(), PROFILE)
    assert not subject.handle(message(tools=[original]))["ok"]
    assert provider.requests == []


@pytest.mark.parametrize("location", ["tool", "namespace", "format", "parameters"])
def test_secret_names_values_and_definitions_never_enter_signed_diagnostics(
    broker, capsys, location  # noqa: F811
):
    state, subject, provider = broker
    original = [custom()] if location == "format" else [function()]
    if location == "namespace":
        original = [{"type": "namespace", "name": "functions", "tools": original}]
    returned = echo(original)
    target = returned[0]
    if location in ("format", "parameters"):
        target = target[location]
    secret = "synthetic-private-tool-property-and-value"
    target.update({secret + str(i): secret for i in range(40)})
    provider.steps = [httpx.Response(200, content=wire(stream(returned)))]
    assert subject.handle(message(tools=original))["outcome"] == "AMBIGUOUS"
    receipts = state.receipts_path.read_text()
    output = capsys.readouterr()
    assert secret not in receipts + output.out + output.err
    assert state.verify_receipts()["ok"]
    rows = [json.loads(line) for line in receipts.splitlines()]
    diag = next(r["inference_observation"] for r in rows if r.get("inference_observation"))
    assert diag["validation_stage"] == "response-tool-echo"
    if location != "parameters":
        assert diag["unexpected_field_count"] == 40
        assert len(diag["unexpected_fields"]) == 16
        assert diag["unexpected_fields_truncated"] is True
        assert all(n.startswith("sha256:") and len(n) == 71 for n in diag["unexpected_fields"])
    diag["tool_rejection_reason"] = "forged"
    state.receipts_path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert not state.verify_receipts()["ok"]
