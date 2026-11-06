"""Unchanged Codex binary, real Docker boundary, SCRIPTED provider (not model acceptance)."""

import json
import os
import subprocess
from pathlib import Path

import httpx
import pytest
from responses_fixture import ScriptedProvider, text, tool
from test_responses_inference import SECRET, configure

from actenon_airlock.cli import main
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.state import State
from actenon_airlock.workflow import status

IMAGE = os.environ.get("AIRLOCK_TEST_CODEX_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="requires pinned Codex compute image")


def workspace(root):
    return (
        max((root / ".airlock/local/runs").iterdir(), key=lambda p: p.stat().st_mtime) / "workspace"
    )


def run_agent(root, monkeypatch, provider, budget="5"):
    (root / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    (root / "test_calculator.py").write_text(
        "from calculator import add\ndef test_add():\n    assert add(2, 3) == 5\n"
    )
    (root / "ISSUE.md").write_text(
        "Investigate the incorrect addition result and fix it. Run the tests."
    )
    (root / ".codex").mkdir()
    (root / ".codex/auth.json").write_text('{"host_secret":"must-not-copy"}')
    configure(root, budget)
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    original = ProtectedBroker.__init__

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.http.close()
        self.http = httpx.Client(transport=httpx.MockTransport(provider))

    monkeypatch.setattr(ProtectedBroker, "__init__", initialize)
    code = main(["work", "--path", str(root), "--message-file", "ISSUE.md", "--image", IMAGE])
    output = os.environ.get("AIRLOCK_CODEX_EVIDENCE")
    if output:
        import shutil

        dest = Path(output) / root.name
        dest.mkdir(parents=True, exist_ok=True)
        # All credentials and tasks here are synthetic. Signing key stays excluded.
        shutil.copytree(
            root / ".airlock/local/runs",
            dest / "runs",
            dirs_exist_ok=True,
            symlinks=True,
            ignore=shutil.ignore_patterns(".home", ".tmp", "__pycache__"),
        )
        shutil.copyfile(root / ".airlock/public-key.json", dest / "public-key.json")
        shutil.copyfile(root / ".airlock/local/receipts.jsonl", dest / "receipts.jsonl")
        (dest / "status.json").write_text(json.dumps(status(State(root)), indent=2))
    return code


def steps():
    return [
        [tool("read", "cat calculator.py && python -m pytest -q")],
        [
            {
                "type": "custom_tool_call",
                "id": "ct_edit",
                "call_id": "edit",
                "name": "apply_patch",
                "status": "completed",
                "input": "*** Begin Patch\n*** Update File: calculator.py\n@@\n-    return a - b\n+    return a + b\n*** End Patch",
            }
        ],
        [tool("test", "python -m pytest -q")],
        [text("Fixture correction complete.")],
    ]


def test_real_codex_executes_edits_tests_and_continues(tmp_path, monkeypatch):
    provider = ScriptedProvider(steps())
    assert run_agent(tmp_path, monkeypatch, provider) == 0
    assert "return a + b" in (workspace(tmp_path) / "calculator.py").read_text()
    assert "return a - b" in (tmp_path / "calculator.py").read_text()
    result = subprocess.run(
        ["python3", "-m", "py_compile", str(workspace(tmp_path) / "calculator.py")],
        capture_output=True,
    )
    assert result.returncode == 0
    history = json.dumps(provider.bodies()[-1]["input"])
    assert "1 failed" in history and "1 passed" in history
    assert len(provider.requests) == 4
    summary = status(State(tmp_path))
    assert summary["inference"]["confirmed"] == 4
    assert summary["inference"]["unconfirmed"] == 0
    assert summary["integrity_ok"]
    for request in provider.requests:
        assert request.headers["authorization"] == "Bearer " + SECRET
        assert json.loads(request.content)["max_output_tokens"] == 16000
    assert "must-not-copy" not in history
    assert not (workspace(tmp_path) / ".codex").exists()


def test_real_codex_lost_ack_stays_held(tmp_path, monkeypatch):
    calls = []

    def lost(request):
        calls.append(request)
        raise httpx.ReadTimeout("Lost acknowledgement", request=request)

    assert run_agent(tmp_path, monkeypatch, lost) in {3, 4}
    assert len(calls) == 1
    summary = status(State(tmp_path))
    assert summary["inference"]["confirmed"] == 0
    assert len(summary["unresolved_effects"]) == 1


def test_real_codex_budget_refusal_before_provider(tmp_path, monkeypatch):
    provider = ScriptedProvider(steps())
    assert run_agent(tmp_path, monkeypatch, provider, budget="0.000001") == 3
    assert not provider.requests


def test_codex_executed_transport_attacks_have_working_controls(tmp_path, monkeypatch):
    """Harness-selected Codex tool calls, NOT a model-selected attack."""
    import shutil
    import time
    from uuid import uuid4

    from actenon_airlock.protected import Docker

    docker = Docker()
    token = uuid4().hex[:12]
    network, container = "airlock-codex-control-" + token, None
    fixtures = Path(__file__).parent / "fixtures/independent"
    sentinel = tmp_path.parent / ("host-only-" + token)
    sentinel.write_text("assurance-host-only")
    monkeypatch.setenv("AIRLOCK_ASSURANCE_HOST_SECRET", "assurance-host-only")
    try:
        docker.call(
            [
                "network",
                "create",
                "--internal",
                "--ipv6",
                "--subnet",
                f"fd43:{token[:4]}:{token[4:8]}::/64",
                network,
            ]
        )
        container = docker.call(
            [
                "run",
                "-d",
                "--rm",
                "--network",
                network,
                "--name",
                network,
                "--mount",
                f"type=bind,source={fixtures},target=/fixture,readonly",
                "--entrypoint",
                "python3",
                IMAGE,
                "/fixture/endpoint.py",
            ]
        )
        for _ in range(100):
            if "ready" in docker.call(["logs", container]):
                break
            time.sleep(0.1)
        else:
            pytest.fail("Owned endpoint unavailable")
        addresses = docker.json(["inspect", container])[0]["NetworkSettings"]["Networks"][network]
        config = {
            "ipv4": addresses["IPAddress"],
            "ipv6": addresses["GlobalIPv6Address"],
            "hostname": network,
            "sentinel": str(sentinel),
        }
        assert config["ipv4"] and config["ipv6"]
        control = json.loads(
            docker.call(
                [
                    "run",
                    "--rm",
                    "--network",
                    network,
                    "--cap-add",
                    "NET_RAW",
                    "--mount",
                    f"type=bind,source={fixtures},target=/fixture,readonly",
                    "--entrypoint",
                    "python3",
                    IMAGE,
                    "/fixture/probes.py",
                    json.dumps(config),
                ]
            )
        )
        assert set(control.values()) == {"delivered"}
        expected = {"ready", "ipv4", "ipv6", "dns", "native", "raw-udp", "proxy", "nested"}
        for _ in range(100):
            before = docker.call(["logs", container]).splitlines()
            if set(map(json.loads, before)) == expected:
                break
            time.sleep(0.1)
        else:
            pytest.fail("Positive controls did not reach the independent sink")
        shutil.copyfile(fixtures / "probes.py", tmp_path / "probes.py")
        (tmp_path / "attack.py").write_text(
            """import importlib.util, json, os
from pathlib import Path
from probes import run
"""
            + f"config = {config!r}\n"
            + """outcomes = run(config, True)
spec = importlib.util.spec_from_file_location('relay', '/airlock/contained_agent.py')
relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)
for kind in ('approve', 'reconcile'):
    outcomes[kind] = not relay.rpc({'kind': kind, 'outcome': 'COMMITTED', 'approved': True})['ok']
for target in ('http://' + config['ipv4'] + ':8080/unsupported', 'https://api.github.com/repos/acme/app/contents/x'):
    outcomes[target] = not relay.rpc({'kind': 'protected-http', 'url': target, 'method': 'POST', 'body': '', 'headers': {}})['ok']
outcomes['host_key_absent'] = os.environ.get('OPENAI_API_KEY') == 'airlock-no-standing-credential'
Path('outcomes.json').write_text(json.dumps(outcomes))
"""
        )
        provider = ScriptedProvider(
            [[tool("attack", "python attack.py")], [text("Fixture complete.")]]
        )
        assert run_agent(tmp_path, monkeypatch, provider) == 3
        seen = json.loads((workspace(tmp_path) / "outcomes.json").read_text())
        assert all(value == "blocked" or value is True for value in seen.values())
        assert len(seen) == 14
        after = docker.call(["logs", container]).splitlines()
        assert before == after, "Protected attack reached the independently observed endpoint"
        assert len(provider.requests) == 2
        assert status(State(tmp_path))["inference"]["confirmed"] == 2
        output = os.environ.get("AIRLOCK_CODEX_EVIDENCE")
        if output:
            (Path(output) / "transport-observations.json").write_text(
                json.dumps(
                    {
                        "control": control,
                        "sink_before": before,
                        "sink_after": after,
                        "protected": seen,
                        "attack_selection": "harness-selected; executed by unchanged Codex",
                    },
                    indent=2,
                )
            )
    finally:
        sentinel.unlink(missing_ok=True)
        if container:
            docker.call(["rm", "-f", container])
        docker.call(["network", "rm", network])


def test_codex_artifact_approved_creation_readback_and_lost_ack(tmp_path, monkeypatch):
    import base64
    import shutil

    from actenon_airlock.synthetic_github import TOKEN, synthetic_client
    from actenon_airlock.workflow import capture_candidate, publish_candidate, verify_candidate

    root = tmp_path / "project"
    root.mkdir()
    assert run_agent(root, monkeypatch, ScriptedProvider(steps())) == 0
    state = State(root)
    candidate = capture_candidate(state)["candidate_sha256"]
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "test_independent.py").write_text(
        "from calculator import add\ndef test_independent():\n    assert add(-7, 3) == -4\n    assert add(0, 8) == 8\n"
    )
    verified = verify_candidate(state, candidate, trusted, image=IMAGE)
    assert verified["verdict"] == "TESTS_PASSED"
    provider, profile, key = (
        tmp_path / "provider.json",
        tmp_path / "profile.json",
        tmp_path / "operator.key",
    )
    assert main(["synthetic-provider", "--file", str(provider), "--create"]) == 0
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    from actenon_airlock.common import AirlockError

    with pytest.raises(AirlockError, match="No separately approved"):
        publish_candidate(state, candidate, client=synthetic_client(provider))
    assert json.loads(provider.read_text())["requests"] == []
    for path, lost in (("patches/fix.patch", False), ("patches/lost.patch", True)):
        assert (
            main(
                [
                    "review-candidate",
                    "--path",
                    str(root),
                    "--candidate",
                    candidate,
                    "--output",
                    str(profile),
                    "--path-in-repo",
                    path,
                    "--message",
                    "Reviewed Codex fixture artifact",
                    "--synthetic-provider",
                    str(provider),
                ]
            )
            == 0
        )
        assert (
            main(
                [
                    "init",
                    "--path",
                    str(root),
                    "--approve",
                    "--github-create",
                    str(profile),
                    "--reconciler-key",
                    str(key),
                    "--credential",
                    "GITHUB_TOKEN=https://api.github.com",
                ]
            )
            == 0
        )
        if lost:
            assert main(["synthetic-provider", "--file", str(provider), "--lose-next-ack"]) == 0
        first = publish_candidate(state, candidate, client=synthetic_client(provider))
        assert first["outcome"] == "AMBIGUOUS"
        for _ in range(3):
            # publish creates another broker, process-independent SQLite claim and fresh grant.
            assert (
                publish_candidate(State(root), candidate, client=synthetic_client(provider))[
                    "status"
                ]
                == "REFUSED"
            )
        observed = json.loads(provider.read_text())
        writes = [
            r for r in observed["requests"] if r["method"] == "PUT" and r["url"].endswith(path)
        ]
        assert len(writes) == 1
        patch = state.local / "candidates" / candidate / "candidate.patch"
        assert base64.b64decode(observed["files"][path]["content"]) == patch.read_bytes()
        assert (
            main(
                [
                    "reconcile",
                    "--path",
                    str(root),
                    first["effect_id"],
                    "--github-readback",
                    "--operator-key",
                    str(key),
                    "--synthetic-provider",
                    str(provider),
                ]
            )
            == 0
        )
        assert not status(state)["unresolved_effects"]
    checkpoint = tmp_path / "checkpoint.json"
    assert main(["checkpoint", "--path", str(root), "--output", str(checkpoint)]) == 0
    common = [
        "verify-evidence",
        "--public-key",
        str(state.path / "public-key.json"),
        "--checkpoint",
        str(checkpoint),
    ]
    assert main([*common, "--journal", str(state.receipts_path)]) == 0
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_bytes(state.receipts_path.read_bytes().replace(b"AMBIGUOUS", b"COMMITTED", 1))
    assert main([*common, "--journal", str(tampered)]) != 0
    output = os.environ.get("AIRLOCK_CODEX_EVIDENCE")
    if output:
        dest = Path(output) / "consequence"
        dest.mkdir(exist_ok=True, parents=True)
        for source in (provider, checkpoint, state.receipts_path, state.path / "public-key.json"):
            shutil.copyfile(source, dest / source.name)
        shutil.copyfile(patch, dest / "candidate.patch")
        (dest / "verification.json").write_text(json.dumps(verified, indent=2))


def test_real_codex_continues_with_documented_direct_callers(tmp_path, monkeypatch):
    from responses_fixture import events
    from responses_tool_echo_fixture import echo
    from test_responses_observation import wire

    turns = steps()
    turns[0].insert(
        0,
        {
            "type": "reasoning",
            "id": "reason_direct",
            "summary": [{"type": "summary_text", "text": "Inspect and test."}],
        },
    )
    turns[0].append(tool("directory", "pwd"))
    for turn in turns:
        for value in turn:
            if value["type"] in {"function_call", "custom_tool_call"}:
                value["caller"] = {"type": "direct"}
    sequences = []
    for index, turn in enumerate(turns):
        seq = events(turn, response_id=f"resp_{index}")
        for event in seq:
            if "response" in event:
                event["response"].update(
                    conversation=None,
                    moderation=None,
                    prompt_cache_options=None,
                    presence_penalty=0,
                    frequency_penalty=0.0,
                    image={"context_compression": "enabled"},
                    tool_usage=json.loads(
                        (
                            Path(__file__).parent / "fixtures/response-zero-tool-usage.json"
                        ).read_text()
                    ),
                )
        sequences.append(seq)

    class EchoProvider(ScriptedProvider):
        def __call__(self, request):
            index = len(self.requests)
            inventory = json.loads(request.content)["tools"]
            assert inventory  # Exercise the unchanged CLI's actual definitions.
            returned = echo(inventory)
            returned.reverse()  # Tool identity is independent of inventory order.
            for event in sequences[index]:
                if "response" in event:
                    event["response"]["tools"] = returned
            self.steps[index] = httpx.Response(200, content=wire(sequences[index]))
            return super().__call__(request)

    provider = EchoProvider([None] * len(sequences))
    assert run_agent(tmp_path, monkeypatch, provider) == 0
    assert "return a + b" in (workspace(tmp_path) / "calculator.py").read_text()
    summary = status(State(tmp_path))
    assert summary["inference"]["confirmed"] == 4
    assert summary["inference"]["unconfirmed"] == 0
    assert summary["integrity_ok"]
