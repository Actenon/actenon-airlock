"""Stage 4 Protected Runner: sets up Airlock protected environment and launches driver."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from actenon_airlock.cli import main as airlock_main
from actenon_airlock.manifest import discover
from actenon_airlock.protected import launch_protected
from actenon_airlock.state import State

from problem_setup import BUGGY_RATE_LIMITER, WORKSPACE_TESTS, create_independent_tests

def run_pytest(test_path: Path) -> tuple[int, str]:
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", str(test_path)],
        capture_output=True,
        text=True,
    )
    return res.returncode, res.stdout + res.stderr

def run_protected():
    ts = int(time.time())
    case = Path(f"/Users/ross/.gemini/antigravity/scratch/field_test_7/protected_case_{ts}").resolve()
    case.mkdir(parents=True, exist_ok=True)
    print(f"[Stage 4] Created protected case directory: {case}")

    # Copy gpt_engineer package
    gpt_eng_src = Path("/Users/ross/.gemini/antigravity/scratch/external-gpt-engineer-source/gpt_engineer")
    shutil.copytree(gpt_eng_src, case / "gpt_engineer")

    # Copy problem files
    (case / "rate_limiter.py").write_text(BUGGY_RATE_LIMITER)
    (case / "test_rate_limiter.py").write_text(WORKSPACE_TESTS)

    # Copy preprompts
    preprompts_src = Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/airlock-agent-preprompts")
    shutil.copytree(preprompts_src, case / "airlock-agent-preprompts")

    # Copy driver
    shutil.copyfile(
        Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/stage4_driver.py"),
        case / "stage4_driver.py",
    )

    # Independent tests
    indep_dir = Path(f"/Users/ross/.gemini/antigravity/scratch/field_test_7/independent_tests_{ts}").resolve()
    create_independent_tests(indep_dir)

    # Configure environment for model discovery & approval
    endpoint = "http://127.0.0.1:11434/v1/chat/completions"
    os.environ["OPENAI_BASE_URL"] = "http://127.0.0.1:11434/v1"
    os.environ["OPENAI_API_BASE"] = "http://127.0.0.1:11434/v1"

    authority = discover(case)
    print(f"[Stage 4] Discovered authority powers: {len(authority['powers'])}")

    init_exit = airlock_main([
        "init",
        "--path", str(case),
        "--approve",
        "--model", "qwen2.5-coder:7b",
        "--model-endpoint", endpoint,
        "--model-max-tokens", "1536",
        "--model-read-timeout", "600",
    ])
    print(f"[Stage 4] Airlock init exit code: {init_exit}")
    assert init_exit == 0, "Airlock init --approve must succeed"

    # Pause 1s for VirtioFS cache coherence
    time.sleep(1.0)

    print("[Stage 4] Launching Protected Mode container with actenon-airlock-gpt-engineer:acceptance...")
    state = State(case)
    t0 = time.time()
    result_code = launch_protected(
        case,
        ["python3", "stage4_driver.py"],
        image="actenon-airlock-gpt-engineer:acceptance",
    )
    elapsed = time.time() - t0
    print(f"[Stage 4] Protected launch returned exit code: {result_code} in {elapsed:.2f}s")

    # Find run artifacts
    runs = sorted((state.local / "runs").glob("protected_*"))
    assert runs, "Protected run directory must exist"
    latest_run = runs[-1]
    workspace = latest_run / "workspace"

    driver_res = {}
    if (workspace / "driver_result.json").exists():
        driver_res = json.loads((workspace / "driver_result.json").read_text())
    
    boundary_info = {}
    if (latest_run / "boundary.json").exists():
        boundary_info = json.loads((latest_run / "boundary.json").read_text())

    # Independent verification
    final_file = workspace / "rate_limiter.py"
    indep_code = 1
    if final_file.exists():
        shutil.copyfile(final_file, indep_dir / "rate_limiter.py")
        indep_code, indep_out = run_pytest(indep_dir / "test_independent_verification.py")
        print(f"[Stage 4] Independent verification exit code: {indep_code}")

    summary = {
        "phase": "protected_agent_evaluation",
        "container_image": "actenon-airlock-gpt-engineer:acceptance",
        "model": "qwen2.5-coder:7b",
        "agent": "gpt-engineer 0.3.1 (SimpleAgent)",
        "launch_exit_code": result_code,
        "elapsed_seconds": round(elapsed, 2),
        "driver_result": driver_res,
        "boundary_summary": boundary_info,
        "independent_verification_exit": indep_code,
        "independent_verification_passed": indep_code == 0,
        "verdict": "PASS" if (driver_res.get("solved") and indep_code == 0) else "FAIL",
    }

    out_file = Path("/Users/ross/.gemini/antigravity/scratch/field_test_7/stage4_summary.json")
    out_file.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"[Stage 4] Summary saved to {out_file}")
    print(json.dumps(summary, indent=2))
    return summary

if __name__ == "__main__":
    run_protected()
