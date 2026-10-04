"""Real-agent acceptance; export only public evidence, never trusted state."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from actenon_airlock.cli import main
from actenon_airlock.manifest import discover
from actenon_airlock.protected import launch_protected
from actenon_airlock.state import State

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--case", type=Path, required=True)
parser.add_argument("--evidence", type=Path, required=True)
parser.add_argument("--image", default="actenon-airlock-gpt-engineer:acceptance")
args = parser.parse_args()
source, case, evidence = args.source.resolve(), args.case.resolve(), args.evidence.resolve()
head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
assert head == "a90fcd543eedcc0ff2c34561bc0785d2ba83c47e", "Use the frozen external source revision"
evidence.mkdir(parents=True, exist_ok=False)
shutil.copytree(source, case, ignore=shutil.ignore_patterns(".git", "__pycache__"))
for src, dest in (
    ("driver.py", "acceptance_driver.py"),
    ("regression.py", "test_airlock_execution_regression.py"),
):
    shutil.copyfile(Path(__file__).with_name(src), case / dest)
endpoint = "http://127.0.0.1:11434/v1/chat/completions"
os.environ["OPENAI_BASE_URL"] = "http://127.0.0.1:11434/v1"
os.environ["OPENAI_API_BASE"] = "http://127.0.0.1:11434/v1"
authority = discover(case)
(evidence / "discovered-authority.json").write_text(json.dumps(authority, indent=2) + "\n")
assert any(p["action"] == "http.post" and p["transport"] == endpoint for p in authority["powers"])
assert (
    main(
        [
            "init",
            "--path",
            str(case),
            "--approve",
            "--model",
            "qwen3:4b",
            "--model-endpoint",
            endpoint,
            "--model-max-tokens",
            "4096",
        ]
    )
    == 0
)
state = State(case)
target = Path("gpt_engineer/core/default/disk_execution_env.py")
original_hash = hashlib.sha256((case / target).read_bytes()).hexdigest()
error, result = None, None
try:
    result = launch_protected(case, ["python3", "acceptance_driver.py"], image=args.image)
except Exception as exc:
    error = {"type": type(exc).__name__, "reason": str(exc)}
finally:
    for run in sorted((state.local / "runs").glob("protected_*")):
        for name in ("boundary.json", "result.json"):
            if (run / name).exists():
                shutil.copyfile(run / name, evidence / name)
        workspace = run / "workspace"
        for name in ("acceptance.json", "regression-before.log", "regression-after.log"):
            if (workspace / name).exists():
                shutil.copyfile(workspace / name, evidence / name)
        if (workspace / target).exists():
            shutil.copyfile(workspace / target, evidence / "agent-edited-disk-execution-env.py")
    verification = state.verify_receipts()
    if state.receipts_path.exists():
        shutil.copyfile(state.receipts_path, evidence / "receipts.jsonl")
    shutil.copyfile(state.path / "public-key.json", evidence / "public-key.json")
    (evidence / "receipt-verification.json").write_text(
        json.dumps({"ok": verification["ok"], "verified": verification["verified"]}, indent=2)
        + "\n"
    )
    (evidence / "run-summary.json").write_text(
        json.dumps(
            {
                "repository": "https://github.com/gpt-engineer-org/gpt-engineer",
                "source_head": head,
                "agent_version": "0.3.1",
                "model": "qwen3:4b",
                "model_fixture": False,
                "model_digest": "359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7",
                "endpoint": endpoint,
                "launch_result": result,
                "error": error,
                "original_source_unchanged": original_hash
                == hashlib.sha256((case / target).read_bytes()).hexdigest(),
                "full_product_pass": False,
            },
            indent=2,
        )
        + "\n"
    )
    print("Public acceptance evidence:", evidence, flush=True)
if error:
    raise RuntimeError(error)
assert result == 3, "Legitimate work succeeds; deliberate unauthorized requests deny the run"
acceptance = json.loads((evidence / "acceptance.json").read_text())
assert acceptance["after_tests"] == "passed" and acceptance["local_commit"]
assert verification["ok"]
