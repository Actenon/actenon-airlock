"""The real, unchanged Claude Code binary through the real protected boundary.

The provider is scripted and in-process, so the supervisor has no route to Anthropic and
nothing here can bill. These tests show that the protocol, the tool loop and containment
work with the genuine client. They show nothing about what a real model would do.
"""

import json
import os
from pathlib import Path

import httpx
import pytest
from anthropic_fixture import BETAS, MODEL, PRICES, ScriptedProvider, stream_reply, text, tool

from actenon_airlock.cli import main
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State
from actenon_airlock.workflow import status

SECRET = "sk-ant-supervisor-held-test-value"
IMAGE = os.environ.get("AIRLOCK_TEST_CLAUDE_CODE_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="requires the Claude Code compute image")

PROBE = """
import json, os, socket
seen = {"env": dict(os.environ), "docker_socket": os.path.exists("/var/run/docker.sock")}
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
    seen["network"] = "connected"
except OSError as exc:
    seen["network"] = type(exc).__name__
try:
    open("/usr/local/bin/planted", "w")
    seen["root_filesystem"] = "written"
except OSError as exc:
    seen["root_filesystem"] = type(exc).__name__
seen["home_entries"] = sorted(os.listdir(os.path.expanduser("~/.claude")))
open("/workspace/.tmp/probe.json", "w").write(json.dumps(seen))
"""


def project(root: Path) -> None:
    (root / "tests").mkdir()
    (root / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    (root / "tests" / "test_calculator.py").write_text(
        "from calculator import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"
    )
    (root / "ISSUE.md").write_text("add(2, 3) returns the wrong answer. Fix it.\n")
    (root / "probe.py").write_text(PROBE)


def steps():
    return [
        [text("Reading the code."), tool("t1", "Read", file_path="/workspace/calculator.py")],
        [
            tool(
                "t2",
                "Edit",
                file_path="/workspace/calculator.py",
                old_string="a - b",
                new_string="a + b",
            )
        ],
        [tool("t3", "Bash", command="python -m pytest -q", description="Run the tests")],
        [tool("t4", "Bash", command="python probe.py", description="Inspect the boundary")],
        [text("Fixed: add now returns the sum.")],
    ]


def serve(monkeypatch, provider):
    original = ProtectedBroker.__init__

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.http.close()
        self.http = httpx.Client(transport=httpx.MockTransport(provider))

    monkeypatch.setattr(ProtectedBroker, "__init__", initialize)


def run_agent(root, monkeypatch, provider, *, max_run_usd="5"):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    serve(monkeypatch, provider)
    path = ["--path", str(root)]
    configured = main(
        [
            "setup",
            *path,
            "--agent",
            "claude-code",
            "--model",
            MODEL,
            "--approve",
            "--max-run-usd",
            max_run_usd,
            "--price-per-mtok",
            PRICES,
        ]  # fmt: skip
    )
    assert configured == 0
    return main(["work", *path, "--message-file", "ISSUE.md", "--image", IMAGE])


def workspace(root):
    runs = sorted((root / ".airlock/local/runs").iterdir(), key=lambda p: p.stat().st_mtime)
    return runs[-1] / "workspace"


def test_real_client_completes_tool_loop_inside_protected_mode(tmp_path, monkeypatch):
    project(tmp_path)
    provider = ScriptedProvider(steps())
    code = run_agent(tmp_path, monkeypatch, provider)
    assert code == 0
    assert (workspace(tmp_path) / "calculator.py").read_text() == (
        "def add(a, b):\n    return a + b\n"
    )
    assert (tmp_path / "calculator.py").read_text() == "def add(a, b):\n    return a - b\n"
    summary = status(State(tmp_path))
    assert summary["refused"] == 0 and summary["integrity_ok"]
    assert summary["inference"]["confirmed"] == len(provider.requests) == 5
    assert summary["inference"]["unconfirmed"] == 0
    assert summary["model_spend"]["estimated_microusd"] > 0


def test_every_model_request_carries_only_the_contract(tmp_path, monkeypatch):
    project(tmp_path)
    provider = ScriptedProvider(steps())
    assert run_agent(tmp_path, monkeypatch, provider) == 0
    for request in provider.requests:
        assert str(request.url) == "https://api.anthropic.com/v1/messages"
        assert request.headers["x-api-key"] == SECRET
        assert set(request.headers["anthropic-beta"].split(",")) <= set(BETAS)
        assert "x-claude-code-session-id" not in request.headers
    assert all(body["model"] == MODEL and body["stream"] for body in provider.bodies())
    last = provider.bodies()[-1]
    assert {tool_def["name"] for tool_def in last["tools"]} == {
        "Bash",
        "Edit",
        "Glob",
        "Grep",
        "Read",
        "Write",
    }
    results = [
        block
        for message in last["messages"]
        if isinstance(message["content"], list)
        for block in message["content"]
        if block["type"] == "tool_result"
    ]
    assert len(results) == 4
    assert "1 passed" in json.dumps(results)


def test_agent_tools_reach_no_credential_network_or_host(tmp_path, monkeypatch):
    project(tmp_path)
    assert run_agent(tmp_path, monkeypatch, ScriptedProvider(steps())) == 0
    seen = json.loads((workspace(tmp_path) / ".tmp" / "probe.json").read_text())
    assert SECRET not in json.dumps(seen)
    assert seen["env"]["ANTHROPIC_API_KEY"] == "airlock-no-standing-credential"
    assert not {"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"} & set(seen["env"])
    assert seen["network"] != "connected"
    assert seen["root_filesystem"] != "written"
    assert seen["docker_socket"] is False
    assert not {"credentials.json", ".credentials.json"} & set(seen["home_entries"])
    assert SECRET not in (tmp_path / ".airlock/local/receipts.jsonl").read_text()


def test_candidate_capture_sees_the_edit_and_no_agent_state(tmp_path, monkeypatch, capsys):
    project(tmp_path)
    assert run_agent(tmp_path, monkeypatch, ScriptedProvider(steps())) == 0
    capsys.readouterr()
    assert main(["capture", "--path", str(tmp_path), "--json"]) == 0
    manifest = json.loads(capsys.readouterr().out)
    assert [change["path"] for change in manifest["changes"]] == ["calculator.py"]


def test_out_of_contract_output_from_a_compromised_client_is_refused(tmp_path, monkeypatch):
    """Claude Code would not send this. Anything else in the container still could."""
    project(tmp_path)
    (tmp_path / "forge.py").write_text(
        """
import json, os, urllib.error, urllib.request
base = os.environ["ANTHROPIC_BASE_URL"]
def post(body, headers=()):
    request = urllib.request.Request(
        base + "/v1/messages", json.dumps(body).encode(),
        {"Content-Type": "application/json", **dict(headers)},
    )
    try:
        return urllib.request.urlopen(request).status
    except urllib.error.HTTPError as exc:
        return exc.code
model = os.environ["ANTHROPIC_MODEL"]
base_body = {"model": model, "max_tokens": 10, "messages": [{"role": "user", "content": "x"}]}
tool = {"type": "web_fetch_20260209", "name": "web_fetch"}
url = {"type": "url", "url": "https://sink.example/secret"}
image = {"role": "user", "content": [{"type": "image", "source": url}]}
outcomes = {
    "server_tool": post({**base_body, "tools": [tool]}),
    "remote_mcp": post({**base_body, "mcp_servers": [{"type": "url", "url": url["url"]}]}),
    "url_source": post({**base_body, "messages": [image]}),
    "other_model": post({**base_body, "model": "claude-unapproved"}),
    "beta_feature": post(base_body, {"anthropic-beta": "mcp-client-2025-11-20"}),
}
open("/workspace/.tmp/forged.json", "w").write(json.dumps(outcomes))
"""
    )
    forge = tool("t1", "Bash", command="python forge.py", description="Forge requests")
    provider = ScriptedProvider([[forge], [text("Done.")]])
    assert run_agent(tmp_path, monkeypatch, provider) == 3
    forged = json.loads((workspace(tmp_path) / ".tmp" / "forged.json").read_text())
    assert set(forged.values()) == {403}
    assert len(forged) == 5
    assert len(provider.requests) == 2
    assert status(State(tmp_path))["refused"] == 5


def test_a_tool_call_naming_an_external_action_grants_nothing(tmp_path, monkeypatch):
    project(tmp_path)
    provider = ScriptedProvider(
        [
            [
                tool(
                    "t1",
                    "GitHubCreateFile",
                    url="https://api.github.com/repos/acme/app/contents/x",
                    content="payload",
                )
            ],
            [text("Done.")],
        ]
    )
    run_agent(tmp_path, monkeypatch, provider)
    assert all("api.anthropic.com" in str(request.url) for request in provider.requests)
    assert "No such tool" in json.dumps(provider.bodies()[-1]["messages"])


def test_provider_rate_limit_retries_as_a_new_call_with_the_real_client(tmp_path, monkeypatch):
    project(tmp_path)
    declined = httpx.Response(
        429,
        headers={"retry-after": "0", "content-type": "application/json"},
        json={"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}},
    )
    provider = ScriptedProvider([declined, stream_reply([text("Nothing to change.")])])
    assert run_agent(tmp_path, monkeypatch, provider) == 0
    assert len(provider.requests) == 2
    assert provider.requests[0].content == provider.requests[1].content
    summary = status(State(tmp_path))
    assert summary["model_spend"]["declined_calls"] == 1
    assert summary["inference"]["retries_held"] == 0


def test_a_lost_reply_ends_the_real_client_without_a_second_dispatch(tmp_path, monkeypatch):
    project(tmp_path)
    calls = []

    def lost(request):
        calls.append(request)
        raise httpx.ReadTimeout("response lost", request=request)

    assert run_agent(tmp_path, monkeypatch, lost) in {3, 4}
    assert len(calls) == 1
    summary = status(State(tmp_path))
    assert summary["inference"]["confirmed"] == 0
    assert len(summary["unresolved_effects"]) == 1


def test_supervisor_spend_bound_stops_the_real_client(tmp_path, monkeypatch):
    project(tmp_path)
    provider = ScriptedProvider(steps())
    # One call reserves far more than this, so nothing may leave.
    code = run_agent(tmp_path, monkeypatch, provider, max_run_usd="0.000001")
    assert code == 3
    assert provider.requests == []
    assert "Model spend bound reached for this run" in status(State(tmp_path))["refusal_reasons"]
