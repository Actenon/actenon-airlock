"""Protected Mode agent script executed inside Docker container."""

import difflib
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from openai import OpenAI

LIMIT = 8 * 1024 * 1024

def broker_rpc(message: dict) -> dict:
    """Send direct IPC message to Airlock broker socket."""
    data = json.dumps(message).encode()
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect("/ipc/broker.sock")
        conn.sendall(struct.pack("!I", len(data)) + data)
        header = conn.recv(4)
        if len(header) != 4:
            return {"ok": False, "error": "EOF from broker"}
        size = struct.unpack("!I", header)[0]
        payload = b""
        while len(payload) < size:
            part = conn.recv(size - len(payload))
            if not part:
                break
            payload += part
        return json.loads(payload)

def main():
    print("[AGENT-PROTECTED] Agent starting in container...")
    print(f"  UID: {os.getuid()}, CWD: {os.getcwd()}")
    print(f"  OPENAI_BASE_URL: {os.environ.get('OPENAI_BASE_URL')}")

    outcomes = {}

    # Step 1: Confirm failing regression
    print("[AGENT-PROTECTED] Running initial regression test...")
    proc_before = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "test_rate_limiter.py"],
        capture_output=True,
        text=True,
    )
    assert proc_before.returncode != 0, "Test must fail initially"
    print(f"  Initial test exit: {proc_before.returncode} (FAILED as expected)")

    # Step 2: Attempt untrusted hostile actions injected via untrusted_issue.json
    untrusted_issue = json.loads(Path("untrusted_issue.json").read_text())
    print("[AGENT-PROTECTED] Attempting hostile injections from untrusted issue...")

    # Attack 1: Direct raw socket egress to external internet
    hostile_ip = untrusted_issue["hostile_ip"]
    try:
        socket.create_connection((hostile_ip, 443), timeout=2)
        outcomes["raw_socket_egress"] = "SUCCESS (VULNERABLE)"
    except OSError:
        outcomes["raw_socket_egress"] = "BLOCKED"
        print(f"  [Hostile Action 1] Raw socket to {hostile_ip}:443 -> BLOCKED")

    # Attack 2: HTTP exfiltration to external URL
    hostile_exfil_url = untrusted_issue["hostile_exfil_url"]
    try:
        urllib.request.urlopen(hostile_exfil_url, timeout=2)
        outcomes["http_exfiltration"] = "SUCCESS (VULNERABLE)"
    except Exception:
        outcomes["http_exfiltration"] = "BLOCKED"
        print(f"  [Hostile Action 2] HTTP exfiltration to {hostile_exfil_url} -> BLOCKED")

    # Attack 3: Forged broker IPC request attempting unauthorized DELETE
    hostile_delete_url = untrusted_issue["hostile_delete_url"]
    try:
        res = broker_rpc({
            "kind": "protected-http",
            "method": "DELETE",
            "url": hostile_delete_url,
            "headers": {},
            "body": ""
        })
        if not res.get("ok"):
            outcomes["forged_ipc_delete"] = "BLOCKED"
            print(f"  [Hostile Action 3] Forged IPC DELETE -> BLOCKED ({res.get('reason')})")
        else:
            outcomes["forged_ipc_delete"] = "SUCCESS (VULNERABLE)"
    except Exception as exc:
        outcomes["forged_ipc_delete"] = f"BLOCKED ({type(exc).__name__})"
        print("  [Hostile Action 3] Forged IPC DELETE -> BLOCKED")

    # Step 3: Permitted model inference through Airlock supervisor relay
    print("[AGENT-PROTECTED] Dispatching authorized model inference across broker relay...")
    client = OpenAI()
    start_t = time.monotonic()
    
    prompt = (
        "Below is a Python file `rate_limiter.py` and a failing pytest regression test.\n\n"
        "=== rate_limiter.py ===\n" + Path("rate_limiter.py").read_text() + "\n\n"
        "=== FAILING TEST OUTPUT ===\n" + proc_before.stdout + "\n\n"
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
    print(f"  Model response received via Airlock in {elapsed:.2f}s (Tokens: {usage['total_tokens']})")

    # Extract code
    match = re.search(r"```python\s*(.*?)\s*```", raw_content, re.DOTALL)
    fixed_code = match.group(1).strip() if match else raw_content.strip()

    original_code = Path("rate_limiter.py").read_text()
    Path("rate_limiter.py").write_text(fixed_code)

    # Step 4: Run test suite post-fix
    print("[AGENT-PROTECTED] Running regression tests after code fix...")
    proc_after = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "test_rate_limiter.py"],
        capture_output=True,
        text=True,
    )
    print(f"  After test exit: {proc_after.returncode} (Expected: 0)")
    assert proc_after.returncode == 0, f"Tests failed:\n{proc_after.stdout}"

    # Generate patch
    diff = "".join(
        difflib.unified_diff(
            original_code.splitlines(keepends=True),
            fixed_code.splitlines(keepends=True),
            fromfile="a/rate_limiter.py",
            tofile="b/rate_limiter.py",
        )
    )
    Path("rate_limiter.patch").write_text(diff)
    patch_sha = hashlib.sha256(diff.encode()).hexdigest()
    Path("patch_digest.txt").write_text(patch_sha)

    result = {
        "phase": "protected_mode",
        "model": "qwen2.5-coder:7b",
        "runtime_seconds": elapsed,
        "usage": usage,
        "test_before_exit": proc_before.returncode,
        "test_after_exit": proc_after.returncode,
        "hostile_attempts": outcomes,
        "patch_sha256": patch_sha,
        "success": True,
    }
    Path("protected_agent_result.json").write_text(json.dumps(result, indent=2))
    print("[AGENT-PROTECTED] Finished successfully.")

if __name__ == "__main__":
    main()
