"""Exercise a real, unmodified milestone checkout against the upgrade candidate.

Only disposable state and an owned loopback HTTP server are used. This is a
harness-selected upgrade control, not a model-selected attack or release gate.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from actenon_airlock.broker import Broker
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import discover
from actenon_airlock.recovery import recovery_inventory
from actenon_airlock.state import State

BASELINE = "341ce3a2f10d2eafa5b07e74539a36e16d3dfac2"
LEGACY_RUN = """
import json, sys
from pathlib import Path
from actenon_airlock.broker import Broker
from actenon_airlock.manifest import discover
from actenon_airlock.state import State
from actenon_permit.model import GrantStatus
root, item, scenario = Path(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3]
state = State(root)
state.approve(dict(discover(root, env={}), command=["main.py"]))
broker = Broker(state, discover(root))
try:
    if scenario == "legacy_nonexecution_without_bound_completion":
        protect = broker.effect_edge.protect
        def revoked(intent, proof, execute):
            broker.store.set_status(broker.grant.id, GrantStatus.REVOKED)
            return protect(intent, proof, execute)
        broker.effect_edge.protect = revoked
    result = broker.handle(item)
    print(json.dumps({"result": result, "source": sys.modules[Broker.__module__].__file__}))
finally:
    broker.close()
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checkout = args.legacy_checkout.resolve()
    sha = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    assert sha == BASELINE, "use the exact reviewed legacy source"
    subprocess.run(["git", "-C", str(checkout), "diff", "--quiet", "HEAD", "--", "src"], check=True)
    calls = []

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"owned-fixture-response")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    report = {"legacy_commit": sha, "model_selected_attack": False, "cases": []}
    try:
        for scenario in (
            "legacy_ambiguous_header_identity",
            "legacy_nonexecution_without_bound_completion",
            "unchanged_identity",
        ):
            with tempfile.TemporaryDirectory(prefix="airlock-legacy-source-") as directory:
                root = Path(directory)
                url = f"http://127.0.0.1:{server.server_port}/{scenario}"
                (root / "main.py").write_text(f'import requests\nrequests.post("{url}")\n')
                item = {
                    "kind": "http",
                    "method": "POST",
                    "url": url,
                    "headers": {}
                    if scenario == "unchanged_identity"
                    else {"Content-Type": "application/json"},
                    "body": "aGVsbG8=",
                    "locations": [{"file": "main.py", "line": 2, "col": 1}],
                }
                process = subprocess.run(
                    [sys.executable, "-c", LEGACY_RUN, str(root), json.dumps(item), scenario],
                    env={
                        "PATH": os.defpath,
                        "PYTHONPATH": str(checkout / "src"),
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                old = json.loads(process.stdout)
                assert Path(old["source"]).is_relative_to(checkout)
                before = calls.count("/" + scenario)
                assert before == (0 if "nonexecution" in scenario else 1)
                state = State(root)
                inventory = recovery_inventory(root)
                item["headers"] = {
                    "Content-Type": "application/json; charset=utf-8",
                    "X-Request-ID": "fresh",
                }
                try:
                    broker = Broker(state, discover(root))
                except AirlockError as exc:
                    new = {"startup_blocked": str(exc)}
                else:
                    try:
                        new = broker.handle(item)
                    finally:
                        broker.close()
                assert calls.count("/" + scenario) == before
                if scenario == "unchanged_identity":
                    assert inventory["status"] == "NO_DETECTED_BLOCKER" and new["ok"] is False
                else:
                    assert inventory["status"] == "BLOCKED" and "startup_blocked" in new
                report["cases"].append(
                    {
                        "scenario": scenario,
                        "legacy_source": old["source"],
                        "legacy_result": old["result"],
                        "upgrade_result": new,
                        "provider_calls_before": before,
                        "provider_calls_after": calls.count("/" + scenario),
                        "inventory": inventory,
                    }
                )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {"legacy_commit": sha, "verified_scenarios": [c["scenario"] for c in report["cases"]]}
        )
    )


if __name__ == "__main__":
    main()
