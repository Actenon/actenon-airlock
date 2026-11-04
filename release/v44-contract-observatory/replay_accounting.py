"""Offline broker comparison against the V4.3 candidate. No provider network calls."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from responses_fixture import ScriptedProvider  # noqa: E402
from responses_full_fixture import EIGHT, full_response  # noqa: E402
from test_responses_inference import SECRET, configure, message  # noqa: E402
from test_responses_observation import wire  # noqa: E402
from test_responses_observatory import CASES, defects  # noqa: E402

from actenon_airlock import protected  # noqa: E402
from actenon_airlock.evidence import (  # noqa: E402
    create_checkpoint,
    load_public_key,
    verify_offline,
)
from actenon_airlock.manifest import discover  # noqa: E402
from actenon_airlock.workflow import status  # noqa: E402

BASE = "208163b8e69058ae2906081893af5db072b45b2a"
source = subprocess.check_output(
    ["git", "show", BASE + ":src/actenon_airlock/responses_inference.py"], cwd=ROOT, text=True
)
spec = importlib.util.spec_from_loader("actenon_airlock.v43_original", loader=None)
original = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = original
exec(source, original.__dict__)
repaired = protected.responses_inference
os.environ["OPENAI_API_KEY"] = SECRET
results = {
    "original_commit": BASE,
    "billing": "Synthetic reviewed-price accounting; no provider billing.",
}
secret = "synthetic-secret"
bad_image = full_response()
bad_image[-1]["response"]["image"] = None
hosted_only = full_response()
hosted_only[-1]["response"]["tool_usage"]["image_gen"]["output_tokens"] = 1
unknown_billing = full_response()
unknown_billing[-1]["response"]["usage"]["synthetic-secret-billing"] = 0
scenarios = [
    ("original_image", original, full_response()),
    ("repaired_enabled", repaired, full_response()),
    ("repaired_disabled", repaired, full_response("disabled")),
    ("repaired_partial", repaired, full_response()[:-1]),
    ("repaired_bad_image", repaired, bad_image),
    ("repaired_hosted_only", repaired, hosted_only),
    ("repaired_unknown_billing", repaired, unknown_billing),
] + [("repaired_" + case, repaired, defects(case)) for case in CASES]
for label, module, seq in scenarios:
    protected.responses_inference = module
    with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
        state = configure(Path(tmp), "0.7")
        provider = ScriptedProvider(
            [
                httpx.Response(200, content=wire(seq)),
                httpx.Response(200, content=wire(full_response())),
            ]
        )
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
                            "inference_observation",
                            "outcome",
                        )
                    }
                    for r in rows
                    if r.get("stage") == "response-received"
                ],
            }
            expected = 1055 if label in {"repaired_enabled", "repaired_disabled"} else 509795
            assert after_first == expected
            assert results[label]["integrity_ok"]
            assert second["ok"] == (label in {"repaired_enabled", "repaired_disabled"})
            assert len(provider.requests) == (
                2 if label in {"repaired_enabled", "repaired_disabled"} else 1
            )
            dest = Path(__file__).with_name("signed-replay") / label
            dest.mkdir(parents=True, exist_ok=True)
            checkpoint = create_checkpoint(state)
            shutil.copyfile(state.receipts_path, dest / "receipts.jsonl")
            shutil.copyfile(state.path / "public-key.json", dest / "public-key.json")
            (dest / "checkpoint.json").write_text(json.dumps(checkpoint, indent=2) + "\n")
            verification = verify_offline(
                state.receipts_path.read_bytes(),
                load_public_key(str(dest / "public-key.json")),
                checkpoint,
            )
            assert verification["ok"] and verification["completeness"]["status"] == "ANCHORED"
            assert secret not in state.receipts_path.read_text()
            (dest / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
        finally:
            subject.close()
protected.responses_inference = repaired
Path(__file__).with_name("accounting-replay.json").write_text(json.dumps(results, indent=2) + "\n")
