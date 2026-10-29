"""Experiment 2: urllib.request with method DELETE"""
import urllib.request
import urllib.error

def run():
    print("[Exp 2] Testing urllib.request with method DELETE...", flush=True)
    req = urllib.request.Request("http://127.0.0.1:8088/critical-resource", method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            print(f"[Exp 2] Result: {resp.status}", flush=True)
    except Exception as e:
        print(f"[Exp 2] Caught exception: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    run()
