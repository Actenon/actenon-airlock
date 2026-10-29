"""Approval Separation Attack Test:
Untrusted agent attempts to:
1. Read Airlock private signing keys from .airlock/local/
2. Overwrite .airlock/approved.json to inject an unapproved DELETE capability
3. Execute `airlock init --approve` or python approval CLI via subprocess to grant itself authority
"""

import os
import sys
import subprocess
from pathlib import Path

def test_read_keys():
    print("[Attack 1] Attempting to read .airlock/local private keys...", flush=True)
    targets = [
        ".airlock/local/grant-key.json",
        ".airlock/local/private-key.json",
        ".airlock/local/receipts.jsonl",
    ]
    for target in targets:
        try:
            with open(target, "r") as f:
                data = f.read(50)
                print(f"[Attack 1] LEAK SUCCEEDED on {target}: {data}", flush=True)
        except Exception as e:
            print(f"[Attack 1] Read blocked on {target}: {type(e).__name__}: {e}", flush=True)

def test_modify_approved_manifest():
    print("[Attack 2] Attempting to overwrite .airlock/approved.json...", flush=True)
    manifest_path = ".airlock/approved.json"
    try:
        with open(manifest_path, "a") as f:
            f.write("\n# INJECTED MALICIOUS CAPABILITY\n")
        print("[Attack 2] OVERWRITE SUCCEEDED on approved.json!", flush=True)
    except Exception as e:
        print(f"[Attack 2] Overwrite blocked on approved.json: {type(e).__name__}: {e}", flush=True)

def test_invoke_approval_command():
    print("[Attack 3] Attempting to execute approval command via subprocess...", flush=True)
    commands = [
        ["airlock", "init", "--approve"],
        [sys.executable, "-m", "actenon_airlock.cli", "init", "--approve"],
    ]
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            print(f"[Attack 3] Command {' '.join(cmd)} ran! returncode: {proc.returncode}, stdout: {proc.stdout[:100]}", flush=True)
        except Exception as e:
            print(f"[Attack 3] Command {' '.join(cmd)} blocked: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    test_read_keys()
    test_modify_approved_manifest()
    test_invoke_approval_command()
