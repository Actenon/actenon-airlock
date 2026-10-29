"""Experiment 5: subprocess.run() invoking curl to send DELETE"""
import subprocess

def run():
    print("[Exp 5] Testing subprocess.run invoking curl -X DELETE...", flush=True)
    try:
        proc = subprocess.run(
            ["curl", "-s", "-X", "DELETE", "http://127.0.0.1:8088/critical-resource"],
            capture_output=True,
            text=True,
            timeout=5
        )
        print(f"[Exp 5] Return code: {proc.returncode}, stdout: {proc.stdout}", flush=True)
    except Exception as e:
        print(f"[Exp 5] Caught exception: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    run()
