"""Offline broker comparison against the V4 candidate. No provider network calls."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from responses_fixture import ScriptedProvider, text  # noqa: E402
from test_response_schema_compatibility import POPULATED, sequence  # noqa: E402
from test_responses_inference import SECRET, configure, message  # noqa: E402
from test_responses_observation import wire  # noqa: E402

from actenon_airlock import protected  # noqa: E402
from actenon_airlock.manifest import discover  # noqa: E402
from actenon_airlock.workflow import status  # noqa: E402

BASE = "61d8bf190107d84cf6c0eb9c06dfd0bbd0f4a7de"
source = subprocess.check_output(
    ["git", "show", BASE + ":src/actenon_airlock/responses_inference.py"], cwd=ROOT, text=True
)
spec = importlib.util.spec_from_loader("actenon_airlock.v4_original", loader=None)
original = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = original
exec(source, original.__dict__)
repaired = protected.responses_inference
os.environ["OPENAI_API_KEY"] = SECRET
results = {
    "original_commit": BASE,
    "billing": "Synthetic reviewed-price accounting; no provider billing.",
}
for label, module, metadata, partial in (
    ("original_null", original, dict.fromkeys(POPULATED), False),
    ("repaired_null", repaired, dict.fromkeys(POPULATED), False),
    ("repaired_populated", repaired, POPULATED, False),
    ("repaired_partial", repaired, dict.fromkeys(POPULATED), True),
):
    protected.responses_inference = module
    with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
        state = configure(Path(tmp), "0.7")
        seq = sequence(metadata)
        if partial:
            seq.pop()
        provider = ScriptedProvider([httpx.Response(200, content=wire(seq)), [text("Continued")]])
        subject = protected.ProtectedBroker(
            state, discover(Path(tmp)), state.approved()["credential_bindings"]
        )
        subject.http.close()
        subject.http = httpx.Client(transport=httpx.MockTransport(provider))
        try:
            first = subject.handle(message())
            after_first = subject.inference_spent
            replay = (
                subject.handle(message(client_metadata={"session_id": "changed"}))
                if first.get("outcome") != "COMMITTED"
                else None
            )
            second = subject.handle(message(instructions="Continue"))
            rows = [json.loads(line) for line in state.receipts_path.read_text().splitlines()]
            results[label] = {
                "first_outcome": first.get("outcome"),
                "after_first_microusd": after_first,
                "second_ok": second["ok"],
                "second_outcome": second.get("outcome"),
                "second_reason": second.get("reason"),
                "replay_refused": replay is not None and not replay["ok"],
                "dispatched": len(provider.requests),
                "total_accounted_microusd": subject.inference_spent,
                "integrity_ok": status(state)["integrity_ok"],
                "observations": [
                    {
                        k: r.get(k)
                        for k in (
                            "inference_reserved_microusd",
                            "inference_cost_microusd",
                            "inference_usage",
                            "outcome",
                        )
                    }
                    for r in rows
                    if r.get("stage") == "response-received"
                ],
            }
            expected = 1055 if label == "repaired_null" else 501335
            assert after_first == expected
            assert results[label]["integrity_ok"]
            assert second["ok"] == (label == "repaired_null")
            assert len(provider.requests) == (2 if label == "repaired_null" else 1)
        finally:
            subject.close()
protected.responses_inference = repaired
Path(__file__).with_name("accounting-replay.json").write_text(json.dumps(results, indent=2) + "\n")
