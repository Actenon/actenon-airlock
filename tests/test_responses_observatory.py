"""Independent diagnostics cannot become authority or accounting evidence."""

import copy
import json

import httpx
import pytest
from responses_fixture import ScriptedProvider
from responses_full_fixture import EIGHT, full_response
from test_responses_inference import PROFILE, REQUEST, SECRET, configure, message
from test_responses_observation import wire
from test_responses_tool_echo import observe

from actenon_airlock import responses_inference as contract
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker


def defects(case):
    seq = full_response()
    final = seq[-1]["response"]
    if case == "unknown-tools":
        final["synthetic-secret-name"] = "synthetic-secret-value"
        final["tools"][0]["parameters"] = {"synthetic-private-schema": "private"}
    elif case == "image-usage":
        final["usage"]["total_tokens"] = 0
    elif case == "image-hosted":
        final["image"] = {"context_compression": "auto"}
        final["tool_usage"]["web_search"]["num_requests"] = 1
    elif case == "incomplete-output":
        seq[-1]["type"] = "response.incomplete"
        final["status"] = "incomplete"
        final["output"] = [{"type": "image_generation_call", "id": "private"}]
    elif case == "strict-state":
        final["tools"][0]["strict"] = "synthetic-secret-value"
        final["conversation"] = {"id": "synthetic-secret-value"}
    elif case == "changed":
        seq[1]["response"]["image"]["context_compression"] = "disabled"
        final["tools"][1]["name"] = "synthetic-secret-tool"
        final["model"] = "synthetic-secret-model"
        final["id"] = "synthetic-secret-id"
    elif case == "billing":
        final["usage"]["synthetic-secret-billing"] = {"price": 0}
        final["tool_usage"]["synthetic-secret-tool"] = {"cost": 0}
    elif case == "sequence":
        seq[1]["sequence_number"] = 100
        seq[1]["response"]["image"] = None
        seq.pop()
    return seq


CASES = {
    "unknown-tools": {"response-schema", "response-tools"},
    "image-usage": {"usage-total"},
    "image-hosted": {"response-image-policy", "response-hosted-tool-usage"},
    "incomplete-output": {"terminal-missing", "output-item-schema"},
    "strict-state": {"response-tools", "response-unsupported-metadata"},
    "changed": {
        "response-image-mismatch",
        "response-tools",
        "response-model",
        "response-id-mismatch",
    },
    "billing": {"usage-schema", "response-tool-usage-schema"},
    "sequence": {"event-sequence", "response-image-schema", "terminal-missing"},
}


@pytest.mark.parametrize("case,expected", CASES.items())
def test_multiple_independent_defects_are_reported_without_confirmation(case, expected):
    result = observe(EIGHT, defects(case))
    assert not result.confirmed and result.usage is None
    report = result.diagnostics["contract_observatory"]
    assert report["authoritative"] is False
    assert expected <= {i["reason"] for i in report["issues"]}, report
    serialized = json.dumps(report)
    assert "synthetic-secret" not in serialized and "synthetic-private" not in serialized
    assert all(i["stage"] and isinstance(i["path"], list) for i in report["issues"])


@pytest.mark.parametrize("streaming", [True, False])
def test_full_valid_contract_has_no_diagnostic_issues(streaming):
    result = observe(EIGHT, full_response(), streaming)
    assert result.confirmed
    assert result.diagnostics["contract_observatory"]["issues"] == []


@pytest.mark.parametrize("case", list(CASES))
def test_multi_defect_accounting_holds_replay_refused_and_diagnostic_signed(
    tmp_path, monkeypatch, capsys, case
):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    state = configure(tmp_path, "0.7")
    provider = ScriptedProvider([httpx.Response(200, content=wire(defects(case)))])
    subject = ProtectedBroker(state, discover(tmp_path), state.approved()["credential_bindings"])
    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(provider))
    try:
        assert subject.handle(message(tools=EIGHT))["outcome"] == "AMBIGUOUS"
        assert subject.inference_spent == 509795
        assert not subject.handle(message(tools=EIGHT, prompt_cache_key="changed"))["ok"]
        next_result = subject.handle(message(tools=EIGHT, instructions="Continue"))
        assert not next_result["ok"]
        assert next_result["reason"] == "Model spend bound reached for this run"
        assert subject.inference_spent == 509795 and len(provider.requests) == 1
        text = state.receipts_path.read_text()
        output = capsys.readouterr()
        assert "synthetic-secret" not in text + output.out + output.err
        assert "synthetic-private" not in text + output.out + output.err
        assert state.verify_receipts()["ok"]
        rows = [json.loads(line) for line in text.splitlines()]
        diagnostic = next(
            r["inference_observation"] for r in rows if r.get("inference_observation")
        )
        diagnostic["contract_observatory"]["issues"][0]["reason"] = "forged"
        state.receipts_path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        assert not state.verify_receipts()["ok"]
    finally:
        subject.close()


@pytest.mark.parametrize("valid", [True, False])
@pytest.mark.parametrize("failure", [False, True])
def test_analyser_cannot_change_verdict_usage_or_inputs(monkeypatch, valid, failure):
    from actenon_airlock import responses_observatory

    seq = full_response() if valid else defects("image-hosted")
    request = json.loads(
        contract.check_request(json.dumps({**REQUEST, "tools": EIGHT}).encode(), PROFILE)
    )
    before = copy.deepcopy(request)
    body = wire(seq)
    authority = contract._observe_authoritative(200, body, request)

    def diagnostic(*args):
        if failure:
            raise RuntimeError("synthetic-secret-exception")
        return {"confirmed": not valid, "usage": {"output_tokens": 0}}

    monkeypatch.setattr(responses_observatory, "inspect_response", diagnostic)
    result = contract.observe(200, body, request)
    assert (result.confirmed, result.declined, result.usage) == (
        authority.confirmed,
        authority.declined,
        authority.usage,
    )
    assert request == before
    assert "synthetic-secret" not in json.dumps(result.diagnostics)


@pytest.mark.parametrize(
    "case", ["depth", "nodes", "events", "issues", "bytes", "malformed", "nonfinite"]
)
def test_inspection_is_bounded_and_does_not_expose_values(case):
    from actenon_airlock import responses_observatory as diagnostic

    request = {**REQUEST, "max_output_tokens": 16000, "tools": EIGHT, "stream": True}
    seq = full_response()
    if case == "depth":
        body = b'{"synthetic-secret":' + b"[" * 100 + b"0" + b"]" * 100 + b"}"
        request["stream"] = False
    elif case == "nodes":
        body = b"[" + b"0," * 10000 + b"0]"
        request["stream"] = False
    elif case == "events":
        body = wire([{"type": "synthetic-secret", "sequence_number": i} for i in range(300)])
    elif case == "issues":
        body = wire(
            [{"type": "response.created", "sequence_number": i, "response": {}} for i in range(100)]
        )
    elif case == "bytes":
        body = b"synthetic-secret" * 300000
    elif case == "nonfinite":
        body = b'{"synthetic-secret":NaN}'
        request["stream"] = False
    else:
        body = b"data: {synthetic-secret}\n\n" + wire(seq)
    report = diagnostic.inspect_response(200, body, request)
    assert len(json.dumps(report).encode()) <= diagnostic.MAX_REPORT_BYTES
    assert len(report["issues"]) <= diagnostic.MAX_ISSUES
    assert all(len(i["path"]) <= diagnostic.MAX_PATH for i in report["issues"])
    assert report["issues"]
    if case in {"depth", "nodes", "events", "issues", "bytes"}:
        assert report["truncated"]
    assert "synthetic-secret" not in json.dumps(report)


def test_separate_usage_and_tool_echo_errors_do_not_mask_each_other():
    seq = full_response()
    final = seq[-1]["response"]
    final["tools"][0]["strict"] = 0
    final["tools"][1]["name"] = "secret"
    final["usage"] = None
    result = observe(EIGHT, seq)
    issues = result.diagnostics["contract_observatory"]["issues"]
    assert {"response-tools", "usage-missing"} <= {i["reason"] for i in issues}
    assert any(i["path"][-1] == 1 and i["stage"] == "tool-echo" for i in issues)
    assert {"field-type", "identity"} <= {i.get("detail") for i in issues}


def test_supported_namespace_strictness_and_reordered_echo_have_no_false_diagnostics():
    from responses_tool_echo_fixture import echo, function, stream

    inventory = [{"type": "namespace", "name": "functions", "tools": [function()]}, function()]
    del inventory[0]["tools"][0]["strict"]
    del inventory[1]["strict"]
    returned = echo(inventory)
    returned[0]["tools"][0]["strict"] = False
    returned[1]["strict"] = True
    seq = stream(returned)
    seq[-1]["response"]["tools"].reverse()
    result = observe(inventory, seq)
    assert result.confirmed
    assert result.diagnostics["contract_observatory"]["issues"] == []


@pytest.mark.parametrize("field", ["output_text", "prompt_cache_diagnostics"])
def test_documented_but_unsupported_names_are_public_identifiers_only(field):
    seq = full_response()
    seq[-1]["response"][field] = "synthetic-secret-value"
    result = observe(EIGHT, seq)
    assert not result.confirmed
    assert result.diagnostics["unexpected_fields"] == [field]
    assert any(
        field in i.get("fields", []) for i in result.diagnostics["contract_observatory"]["issues"]
    )
    assert "synthetic-secret" not in json.dumps(result.diagnostics)


@pytest.mark.parametrize("valid", [True, False])
def test_missing_diagnostic_module_cannot_change_authority(monkeypatch, valid):
    import builtins

    original = builtins.__import__

    def isolated_import(name, *args, **kwargs):
        if name == "responses_observatory":
            raise ImportError("synthetic-secret-import-failure")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", isolated_import)
    result = observe(EIGHT, full_response() if valid else defects("image-hosted"))
    assert result.confirmed is valid
    assert result.diagnostics["contract_observatory"] == {
        "authoritative": False,
        "unavailable": True,
    }
    assert "synthetic-secret" not in json.dumps(result.diagnostics)


def test_exhausted_diagnostic_work_budget_cannot_downgrade_valid_response(monkeypatch):
    from actenon_airlock import responses_observatory

    monkeypatch.setattr(responses_observatory, "MAX_PROBES", 1)
    result = observe(EIGHT, full_response())
    assert result.confirmed and result.usage["output_tokens"] == 20
    report = result.diagnostics["contract_observatory"]
    assert report["probes"] == 1 and report["truncated"]
