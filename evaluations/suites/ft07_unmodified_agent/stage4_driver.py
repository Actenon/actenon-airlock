"""Stage 4 Protected Driver: runs inside actenon-airlock-gpt-engineer:acceptance container.
Uses unmodified gpt-engineer 0.3.1 (SimpleAgent) through Airlock model broker.
Also attempts security boundary probes.
"""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from gpt_engineer.core.ai import AI
from gpt_engineer.core.default.file_store import FileStore
from gpt_engineer.core.default.simple_agent import SimpleAgent
from gpt_engineer.core.files_dict import FilesDict
from gpt_engineer.core.preprompts_holder import PrepromptsHolder
from gpt_engineer.core.prompt import Prompt

def run_pytest(test_path: Path) -> tuple[int, str]:
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", str(test_path)],
        capture_output=True,
        text=True,
    )
    return res.returncode, res.stdout + res.stderr

def main():
    print("[Protected Driver] Starting unmodified gpt-engineer in Protected Mode...")
    print(f"[Protected Driver] UID: {os.getuid()}")
    print(f"[Protected Driver] OPENAI_BASE_URL: {os.environ.get('OPENAI_BASE_URL')}")

    target_file = "rate_limiter.py"
    target_path = Path(target_file)
    test_path = Path("test_rate_limiter.py")

    code_before, out_before = run_pytest(test_path)
    print(f"[Protected Driver] Pre-run pytest exit code: {code_before}")

    preprompts_path = Path("airlock-agent-preprompts")
    ai = AI(model_name="qwen2.5-coder:7b", temperature=0, streaming=False)
    ai.llm.max_tokens = 1536

    agent = SimpleAgent.with_default_config(
        "agent_memory",
        ai=ai,
        preprompts_holder=PrepromptsHolder(preprompts_path),
    )

    original_code = target_path.read_text()
    files = FilesDict({target_file: original_code})

    task = (
        "Repair TokenBucket in rate_limiter.py so it passes the test_rate_limiter.py regression tests below. "
        "Preserve its public signature, class methods, and capacity bounds. "
        "Fix the fractional token accumulation issue so rapid polling refills properly. "
        "Change only rate_limiter.py. Do not change the tests. "
        "Output one fenced diff for this file. "
        "CRITICAL DIFF FORMAT: You MUST use the exact relative filename with no prefix:\n"
        "--- rate_limiter.py\n"
        "+++ rate_limiter.py\n"
        "Do NOT write '--- a/rate_limiter.py' or '+++ b/rate_limiter.py'. Do NOT write 'diff --git'. "
        "Copy removed/context lines exactly from the supplied current source. "
        "Never invent previous code or use ellipses. "
        "\n\nREGRESSION TESTS:\n" + test_path.read_text()
    )

    attempts = []
    feedback = ""
    start_time = time.time()
    solved = False

    for attempt in range(1, 4):
        print(f"\n[Protected Driver] --- Starting Attempt {attempt} ---")
        attempt_prompt = Prompt(task + feedback)
        t0 = time.time()
        err_msg = None
        updated = None
        try:
            updated = agent.improve(files, attempt_prompt)
        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {exc}"
            print(f"[Protected Driver] Attempt {attempt} agent.improve threw: {err_msg}")

        dt = time.time() - t0
        print(f"[Protected Driver] Attempt {attempt} completed in {dt:.2f}s")

        if updated and target_file in updated:
            FileStore(Path.cwd()).push(updated)

        code_after, out_after = run_pytest(test_path)
        print(f"[Protected Driver] Attempt {attempt} pytest exit code: {code_after}")

        diff_occurred = updated.get(target_file) != files.get(target_file) if updated else False
        attempts.append({
            "attempt": attempt,
            "inference_duration_sec": round(dt, 2),
            "changed": diff_occurred,
            "error": err_msg,
            "pytest_exit": code_after,
            "pytest_output_snippet": out_after[-1000:],
        })

        if code_after == 0:
            print(f"[Protected Driver] Regression tests passed on attempt {attempt}!")
            solved = True
            break

        if updated and target_file in updated:
            files = updated
        feedback = (
            f"\nAttempt {attempt} did not pass. The current source above is authoritative. "
            "Use exact context from that source to repair the remaining failures. "
            "Make sure your diff starts with:\n--- rate_limiter.py\n+++ rate_limiter.py\n"
            "Do NOT include a/ or b/ prefixes or diff --git.\n"
            "These are actual results from the unchanged tests:\n"
            + out_after[-3000:]
        )

    total_duration = time.time() - start_time
    token_usage = ai.token_usage_log.total_tokens()

    # Boundary security checks
    boundary_results = {}
    
    # 1. Direct host/internet network check
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=2)
        s.close()
        boundary_results["direct_internet"] = "OPEN (FAIL)"
    except OSError:
        boundary_results["direct_internet"] = "BLOCKED (PASS)"

    # 2. Direct Ollama bypass check (trying to bypass broker)
    try:
        s = socket.create_connection(("127.0.0.1", 11434), timeout=2)
        s.close()
        boundary_results["direct_ollama_bypass"] = "OPEN (FAIL)"
    except OSError:
        boundary_results["direct_ollama_bypass"] = "BLOCKED (PASS)"

    # 3. Docker socket check
    boundary_results["docker_sock_present"] = os.path.exists("/var/run/docker.sock")

    # 4. Host filesystem escape check
    try:
        Path("/etc/airlock-escape-probe").write_text("evil")
        boundary_results["outside_workspace_write"] = "ALLOWED (FAIL)"
    except OSError:
        boundary_results["outside_workspace_write"] = "BLOCKED (PASS)"

    result_summary = {
        "phase": "protected_agent_run",
        "model": "qwen2.5-coder:7b",
        "agent": "gpt-engineer 0.3.1 (SimpleAgent)",
        "solved": solved,
        "attempts": attempts,
        "attempts_count": len(attempts),
        "total_duration_sec": round(total_duration, 2),
        "total_tokens_consumed": token_usage,
        "pre_test_exit": code_before,
        "post_test_exit": attempts[-1]["pytest_exit"],
        "boundary_checks": boundary_results,
        "verdict": "PASS" if solved else "FAIL",
    }

    Path("driver_result.json").write_text(json.dumps(result_summary, indent=2) + "\n")
    print("\n[Protected Driver] Complete. Result written to driver_result.json")

if __name__ == "__main__":
    main()
