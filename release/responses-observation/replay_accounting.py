"""Offline synthetic regression replay. Never sends a provider request."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "tests"))
from responses_fixture import ScriptedProvider, text  # noqa: E402
from test_responses_inference import SECRET, configure, message  # noqa: E402
from test_responses_observation import output  # noqa: E402

from actenon_airlock import protected  # noqa: E402
from actenon_airlock.manifest import discover  # noqa: E402
from actenon_airlock.workflow import status  # noqa: E402

original_source = subprocess.check_output(
    ["git", "show", "1fef597:src/actenon_airlock/responses_inference.py"], cwd=root, text=True
)
spec = importlib.util.spec_from_loader("actenon_airlock.original_responses", loader=None)
original = importlib.util.module_from_spec(spec)
exec(original_source, original.__dict__)
repaired = protected.responses_inference
os.environ["OPENAI_API_KEY"] = SECRET
results = {}
for name, module in [("original_observer", original), ("repaired_observer", repaired)]:
    protected.responses_inference = module
    with tempfile.TemporaryDirectory(dir=root.parent) as tmp:
        state = configure(Path(tmp), "0.7")
        provider = ScriptedProvider([[output()], [text("Continued")]])
        subject = protected.ProtectedBroker(
            state, discover(Path(tmp)), state.approved()["credential_bindings"]
        )
        subject.http.close()
        subject.http = httpx.Client(transport=httpx.MockTransport(provider))
        a = subject.handle(message())
        b = subject.handle(message(instructions="Continue"))
        rows = [json.loads(line) for line in state.receipts_path.read_text().splitlines()]
        results[name] = {
            "first": {"ok": a["ok"], "outcome": a.get("outcome")},
            "second": {"ok": b["ok"], "outcome": b.get("outcome"), "reason": b.get("reason")},
            "dispatched": len(provider.requests),
            "accounted_microusd": subject.inference_spent,
            "receipts": [
                {
                    "stage": r.get("stage"),
                    "outcome": r.get("outcome"),
                    "reserved_microusd": r.get("inference_reserved_microusd"),
                    "accounted_microusd": r.get("inference_cost_microusd"),
                    "usage": r.get("inference_usage"),
                }
                for r in rows
                if r.get("stage") == "response-received"
            ],
            "journal_integrity": status(state)["integrity_ok"],
        }
        subject.close()
results["scope"] = (
    "Specification-derived direct-caller fixture through real Scan, Permit, Kernel and broker, with an httpx synthetic provider. Not original V3.2 SSE, provider billing or live autonomous acceptance."
)
(root / "release/responses-observation/accounting-replay.json").write_text(
    json.dumps(results, indent=2) + "\n"
)
