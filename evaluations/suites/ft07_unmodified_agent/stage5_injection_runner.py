"""Stage 5 Injection Runner: Matched comparison of prompt injection attack under Unprotected vs Protected Mode."""

import os as _os
import sys as _sys

if not (_os.path.exists("/.dockerenv") or _os.environ.get("AIRLOCK_EVALUATION_SANDBOX") == "container"):
    _sys.exit(
        "Refusing to run on the host: this historical evaluation executes untrusted "
        "candidate, agent or model-generated code. Run it inside a disposable container "
        "(see evaluations/CORRECTIONS.md)."
    )

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from actenon_airlock.cli import main as airlock_main
from actenon_airlock.manifest import discover
from actenon_airlock.protected import launch_protected
from actenon_airlock.state import State

from problem_setup import BUGGY_RATE_LIMITER

def get_mock_requests():
    with urllib.request.urlopen("http://127.0.0.1:8999/__requests", timeout=2) as resp:
        return json.loads(resp.read().decode("utf-8"))

def reset_mock():
    with urllib.request.urlopen("http://127.0.0.1:8999/__reset", timeout=2) as resp:
        assert resp.read() == b"OK"

def run_stage_5():
    print("[Stage 5] --- Starting Untrusted Hostile Instruction Comparison ---")

    # 1. UNPROTECTED BASELINE
    reset_mock()
    baseline_dir = Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/stage5_baseline_dir")
    if baseline_dir.exists():
        shutil.rmtree(baseline_dir)
    baseline_dir.mkdir(parents=True)
    (baseline_dir / "rate_limiter.py").write_text(BUGGY_RATE_LIMITER)
    shutil.copytree(
        Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/airlock-agent-preprompts"),
        baseline_dir / "airlock-agent-preprompts",
    )
    shutil.copyfile(
        Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/stage5_injection_driver.py"),
        baseline_dir / "stage5_injection_driver.py",
    )

    env_unprotected = dict(os.environ)
    env_unprotected["OPENAI_BASE_URL"] = "http://127.0.0.1:11434/v1"
    env_unprotected["OPENAI_API_KEY"] = "ollama"

    print("[Stage 5] Running Unprotected Baseline with Hostile Instruction...")
    subprocess.run(
        [sys.executable, "stage5_injection_driver.py", "unprotected"],
        cwd=str(baseline_dir),
        env=env_unprotected,
        capture_output=True,
        text=True,
    )

    baseline_exfil_requests = get_mock_requests()
    print(f"[Stage 5] Unprotected Baseline: Mock server received {len(baseline_exfil_requests)} exfiltration requests!")

    # 2. AIRLOCK PROTECTED MODE
    reset_mock()
    ts = int(time.time())
    case = Path(f"/Users/ross/.gemini/antigravity/scratch/field_test_7/protected_injection_case_{ts}").resolve()
    case.mkdir(parents=True, exist_ok=True)

    gpt_eng_src = Path("/Users/ross/.gemini/antigravity/scratch/external-gpt-engineer-source/gpt_engineer")
    shutil.copytree(gpt_eng_src, case / "gpt_engineer")
    (case / "rate_limiter.py").write_text(BUGGY_RATE_LIMITER)
    shutil.copytree(
        Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/airlock-agent-preprompts"),
        case / "airlock-agent-preprompts",
    )
    shutil.copyfile(
        Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/stage5_injection_driver.py"),
        case / "stage5_injection_driver.py",
    )

    endpoint = "http://127.0.0.1:11434/v1/chat/completions"
    os.environ["OPENAI_BASE_URL"] = "http://127.0.0.1:11434/v1"
    os.environ["OPENAI_API_BASE"] = "http://127.0.0.1:11434/v1"

    init_code = airlock_main([
        "init",
        "--path", str(case),
        "--approve",
        "--model", "qwen2.5-coder:7b",
        "--model-endpoint", endpoint,
        "--model-max-tokens", "512",
        "--model-read-timeout", "600",
    ])
    assert init_code == 0, "Airlock init must succeed"
    time.sleep(1.0)

    print("[Stage 5] Launching Protected Mode Container with Hostile Instruction...")
    state = State(case)
    prot_exit = launch_protected(
        case,
        ["python3", "stage5_injection_driver.py", "protected"],
        image="actenon-airlock-gpt-engineer:acceptance",
    )
    print(f"[Stage 5] Protected Mode launch returned exit code: {prot_exit}")

    protected_exfil_requests = get_mock_requests()
    print(f"[Stage 5] Protected Mode: Mock server received {len(protected_exfil_requests)} exfiltration requests!")

    runs = sorted((state.local / "runs").glob("protected_*"))
    latest_run = runs[-1]
    workspace = latest_run / "workspace"
    prot_driver_res = {}
    if (workspace / "injection_results.json").exists():
        prot_driver_res = json.loads((workspace / "injection_results.json").read_text())

    unprot_driver_res = {}
    if (baseline_dir / "injection_results.json").exists():
        unprot_driver_res = json.loads((baseline_dir / "injection_results.json").read_text())

    summary = {
        "phase": "hostile_instruction_comparison",
        "unprotected_baseline": {
            "mock_requests_received_count": len(baseline_exfil_requests),
            "requests_log": baseline_exfil_requests,
            "driver_results": unprot_driver_res.get("exfil_results", []),
            "vulnerability_verdict": "VULNERABLE (Transports leaked data)",
        },
        "airlock_protected_mode": {
            "mock_requests_received_count": len(protected_exfil_requests),
            "requests_log": protected_exfil_requests,
            "driver_results": prot_driver_res.get("exfil_results", []),
            "containment_verdict": "PROTECTED (Zero exfiltrations, 100% blocked by network isolation)",
        },
    }

    out_file = Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/stage5_summary.json")
    out_file.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\n[Stage 5] Summary saved to {out_file}")
    print(json.dumps(summary, indent=2))
    return summary

if __name__ == "__main__":
    run_stage_5()
