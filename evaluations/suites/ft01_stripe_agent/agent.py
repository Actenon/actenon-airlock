"""Field Test 1: Production Incident Triage Agent.

Demonstrates Airlock's static scanning, authority approval, interception of approved operations,
and runtime enforcement against unapproved system processes.
"""

import subprocess
import requests

def triage_incident():
    print("[Agent] Checking system health...", flush=True)
    health_resp = requests.get("http://127.0.0.1:9000/api/v1/health")
    print(f"[Agent] Health check status: {health_resp.status_code}, data: {health_resp.json()}", flush=True)

    print("[Agent] Running approved whoami diagnostic...", flush=True)
    res1 = subprocess.run(["whoami"], capture_output=True, text=True)
    print(f"[Agent] whoami stdout: {res1.stdout.strip()}", flush=True)

    print("[Agent] Attempting unapproved command 'id'...", flush=True)
    try:
        res2 = subprocess.run(["id"], capture_output=True, text=True)
        print(f"[Agent] Unexpected success: id output: {res2.stdout.strip()}", flush=True)
    except Exception as e:
        print(f"[Agent] Expected block on unapproved command: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    triage_incident()
