"""Offline broker comparison against the V4.2 candidate. No provider network calls."""

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
from responses_tool_echo_fixture import EIGHT, echo, stream as sequence  # noqa: E402
from test_responses_inference import SECRET, configure, message  # noqa: E402
from test_responses_observation import wire  # noqa: E402

from actenon_airlock import protected  # noqa: E402
from actenon_airlock.manifest import discover  # noqa: E402
from actenon_airlock.workflow import status  # noqa: E402

BASE = "9d1edf8172fbc5e3b3ea05293e94f2a1dc166343"
source = subprocess.check_output(
    ["git", "show", BASE + ":src/actenon_airlock/responses_inference.py"], cwd=ROOT, text=True
)
spec = importlib.util.spec_from_loader("actenon_airlock.v42_original", loader=None)
original = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = original
exec(source, original.__dict__)
repaired = protected.responses_inference
os.environ["OPENAI_API_KEY"] = SECRET
results = {
    "original_commit": BASE,
    "billing": "Synthetic reviewed-price accounting; no provider billing.",
}
changed = echo(EIGHT)
changed[0]["parameters"] = {}
programmatic = echo(EIGHT)
programmatic[0]["allowed_callers"] = ["programmatic"]
for label, module, metadata, partial in (
    ("original_echo", original, echo(EIGHT), False),
    ("repaired_echo", repaired, echo(EIGHT), False),
    ("repaired_changed_schema", repaired, changed, False),
    ("repaired_programmatic", repaired, programmatic, False),
    ("repaired_partial", repaired, echo(EIGHT), True),
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
            first = subject.handle(message(tools=EIGHT))
            after_first = subject.inference_spent
            replay = (
                subject.handle(message(tools=EIGHT, client_metadata={"session_id": "changed"}))
                if first.get("outcome") != "COMMITTED"
                else None
            )
            second = subject.handle(message(tools=EIGHT, instructions="Continue"))
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
            expected = 1055 if label == "repaired_echo" else 509795
            assert after_first == expected
            assert results[label]["integrity_ok"]
            assert second["ok"] == (label == "repaired_echo")
            assert len(provider.requests) == (2 if label == "repaired_echo" else 1)
        finally:
            subject.close()
protected.responses_inference = repaired
Path(__file__).with_name("accounting-replay.json").write_text(json.dumps(results, indent=2) + "\n")
