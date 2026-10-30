"""Real Linux boundary, with functioning IPv4/IPv6/native/raw/DNS/proxy controls."""

import json
import os
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import pytest

from actenon_airlock.manifest import discover
from actenon_airlock.protected import Docker, launch_protected
from actenon_airlock.state import State


def test_owned_transport_controls_and_protected_boundary(tmp_path, monkeypatch):
    image = os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE")
    if not image:
        pytest.skip("requires explicitly configured disposable Docker image")
    docker = Docker()
    docker.verify_engine()
    token = uuid4().hex[:12]
    network, container = "airlock-assurance-" + token, None
    fixtures = Path(__file__).parent / "fixtures" / "independent"
    root = tmp_path / "project"
    root.mkdir()
    sentinel = tmp_path / "host-only"
    sentinel.write_text("assurance-host-only")
    monkeypatch.setenv("AIRLOCK_ASSURANCE_HOST_SECRET", "assurance-host-only")
    observed = []

    class Model(BaseHTTPRequestHandler):
        def do_POST(self):
            observed.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "model": "fixture",
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                        "choices": [
                            {
                                "finish_reason": "stop",
                                "message": {"role": "assistant", "content": "approved"},
                            }
                        ],
                    }
                ).encode()
            )

        def log_message(self, *args):
            pass

    provider = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{provider.server_port}/v1/chat/completions"
    try:
        docker.call(
            [
                "network",
                "create",
                "--internal",
                "--ipv6",
                "--subnet",
                f"fd42:{token[:4]}:{token[4:8]}::/64",
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
                image,
                "/fixture/endpoint.py",
            ]
        )
        for _ in range(100):
            if "ready" in docker.call(["logs", container]):
                break
            time.sleep(0.1)
        else:
            pytest.fail("owned endpoint did not become ready")
        config = docker.json(["inspect", container])[0]["NetworkSettings"]["Networks"][network]
        config = {
            "ipv4": config["IPAddress"],
            "ipv6": config["GlobalIPv6Address"],
            "hostname": network,
            "sentinel": str(sentinel),
        }
        assert config["ipv4"] and config["ipv6"]
        control = docker.call(
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
                image,
                "/fixture/probes.py",
                json.dumps(config),
            ]
        )
        assert set(json.loads(control).values()) == {"delivered"}
        expected = {"ready", "ipv4", "ipv6", "dns", "native", "raw-udp", "proxy", "nested"}
        for _ in range(100):
            before = docker.call(["logs", container]).splitlines()
            if set(map(json.loads, before)) == expected:
                break
            time.sleep(0.1)
        else:
            pytest.fail("transport controls did not reach the independent sink")
        shutil.copyfile(fixtures / "probes.py", root / "probes.py")
        (root / "main.py").write_text(
            """import base64, importlib.util, json
from pathlib import Path
if False:
    import requests
from probes import run
"""
            + f"requests.post({url!r}) if False else None\n"
            + f"config = {config!r}\n"
            + """outcomes = run(config, True)
spec = importlib.util.spec_from_file_location('relay', '/airlock/contained_agent.py')
relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)
Path('.airlock').mkdir()
Path('.airlock/approved.json').write_text('{"powers":["*"]}')
for kind in ('approve', 'reconcile'):
    assert not relay.rpc({'kind':kind, 'outcome':'COMMITTED', 'approved':True})['ok']
    outcomes[kind] = 'blocked'
assert not relay.rpc({'kind':'protected-http', 'url':'http://' + config['ipv4'] + ':8080/unsupported',
    'method':'POST', 'body':'', 'headers':{}})['ok']
outcomes['unsupported-http'] = 'blocked'
"""
            + f"url = {url!r}\n"
            + """body = {'model':'fixture','messages':[{'role':'user','content':'owned control'}]}
result = relay.rpc({'kind':'protected-http','url':url,'method':'POST','headers':{},
    'body':base64.b64encode(json.dumps(body).encode()).decode()})
assert result['ok'], result
Path('outcomes.json').write_text(json.dumps(outcomes))
"""
        )
        state = State(root)
        state.approve(
            {
                **discover(root, env={}),
                "protected_model": {
                    "provider": "openai",
                    "endpoint": url,
                    "models": ["fixture"],
                    "max_output_tokens": 16,
                },
            }
        )
        assert launch_protected(root, ["python3", "main.py"], image=image) == 3
        run = next((state.local / "runs").iterdir())
        outcomes = json.loads((run / "workspace" / "outcomes.json").read_text())
        assert set(outcomes.values()) == {"blocked"} and len(outcomes) == 12
        after = docker.call(["logs", container]).splitlines()
        assert after == before, "protected probe reached the independently observed sink"
        assert len(observed) == 1 and observed[0]["max_tokens"] == 16
        assert sentinel.read_text() == "assurance-host-only"
        assert state.verify_receipts()["ok"]
        output = os.environ.get("AIRLOCK_INDEPENDENT_EVIDENCE")
        if output:
            destination = Path(output)
            destination.mkdir(parents=True, exist_ok=True)
            for name in ("boundary.json", "result.json"):
                shutil.copyfile(run / name, destination / name)
            (destination / "transport-observations.json").write_text(
                json.dumps(
                    {
                        "control": json.loads(control),
                        "protected": outcomes,
                        "sink_before": before,
                        "sink_after": after,
                        "approved_inference": observed,
                        "model_selected_attack": False,
                    },
                    indent=2,
                )
            )
            shutil.copyfile(state.receipts_path, destination / "receipts.jsonl")
            shutil.copyfile(state.path / "public-key.json", destination / "public-key.json")
    finally:
        provider.shutdown()
        provider.server_close()
        if container:
            docker.call(["rm", "-f", container])
        docker.call(["network", "rm", network])
