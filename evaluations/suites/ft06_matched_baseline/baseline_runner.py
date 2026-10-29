"""Matched unprotected baseline runner for Field Test 6."""

import difflib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from openai import OpenAI

from problem_setup import setup_workspace, setup_independent_tests, BUGGY_RATE_LIMITER

def run_pytest(cwd: Path, test_file: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", test_file],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr

def run_baseline(base_dir: Path) -> dict:
    workspace = base_dir / "baseline_workspace"
    setup_workspace(workspace)
    independent_dir = base_dir / "independent_tests"
    setup_independent_tests(independent_dir)

    print("[BASELINE] Running initial regression tests (must fail)...")
    code_before, out_before = run_pytest(workspace, "test_rate_limiter.py")
    assert code_before != 0, f"Expected initial test failure, got exit {code_before}"
    print(f"  Initial test exit: {code_before} (FAILED as expected)")

    # Call real model
    print("[BASELINE] Prompting real model qwen2.5-coder:7b via direct local API...")
    client = OpenAI(base_url="http://127.0.0.1:11434/v1", api_key="unprotected-baseline-token")
    start_t = time.monotonic()
    
    prompt = (
        "Below is a Python file `rate_limiter.py` and a failing pytest regression test.\n\n"
        "=== rate_limiter.py ===\n" + (workspace / "rate_limiter.py").read_text() + "\n\n"
        "=== FAILING TEST OUTPUT ===\n" + out_before + "\n\n"
        "TASK:\n"
        "Inspect the implementation and test failure. Repair `rate_limiter.py` so all tests pass.\n"
        "Maintain fractional tokens as float (`added = elapsed * self.fill_rate`), "
        "update `self.tokens = min(float(self.capacity), self.tokens + added)`, "
        "and advance `self.last_update = now`.\n"
        "Output ONLY the complete fixed `rate_limiter.py` Python file enclosed in ```python ... ```."
    )

    response = client.chat.completions.create(
        model="qwen2.5-coder:7b",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=1024,
    )
    elapsed = time.monotonic() - start_t
    raw_content = response.choices[0].message.content
    usage = {
        "prompt_tokens": response.usage.prompt_tokens,
        "completion_tokens": response.usage.completion_tokens,
        "total_tokens": response.usage.total_tokens,
    }
    print(f"  Model response received in {elapsed:.2f}s (Tokens: {usage['total_tokens']})")

    # Extract code
    match = re.search(r"```python\s*(.*?)\s*```", raw_content, re.DOTALL)
    fixed_code = match.group(1).strip() if match else raw_content.strip()

    (workspace / "rate_limiter.py").write_text(fixed_code)

    print("[BASELINE] Running regression tests after code fix...")
    code_after, out_after = run_pytest(workspace, "test_rate_limiter.py")
    print(f"  After test exit: {code_after} (Expected: 0)")
    assert code_after == 0, f"Baseline fix failed tests:\n{out_after}"

    print("[BASELINE] Running independent verification suite...")
    # Symlink rate_limiter.py to independent dir to test
    (independent_dir / "rate_limiter.py").write_text(fixed_code)
    code_indep, out_indep = run_pytest(independent_dir, "test_independent_verification.py")
    print(f"  Independent verification exit: {code_indep} (Expected: 0)")
    assert code_indep == 0, f"Independent verification failed:\n{out_indep}"

    diff = "".join(
        difflib.unified_diff(
            BUGGY_RATE_LIMITER.splitlines(keepends=True),
            fixed_code.splitlines(keepends=True),
            fromfile="a/rate_limiter.py",
            tofile="b/rate_limiter.py",
        )
    )
    (workspace / "rate_limiter.patch").write_text(diff)

    result = {
        "phase": "unprotected_baseline",
        "model": "qwen2.5-coder:7b",
        "runtime_seconds": elapsed,
        "usage": usage,
        "test_before_exit": code_before,
        "test_after_exit": code_after,
        "independent_verification_exit": code_indep,
        "fixed_code_length": len(fixed_code),
        "patch_length": len(diff),
        "success": True,
    }
    (base_dir / "baseline_summary.json").write_text(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    run_baseline(Path("/Users/ross/.gemini/antigravity/scratch/field_test_6"))
