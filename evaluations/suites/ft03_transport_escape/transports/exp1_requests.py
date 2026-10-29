"""Experiment 1: Standard requests.delete()"""
import requests

def run():
    print("[Exp 1] Testing requests.delete() to unapproved endpoint...", flush=True)
    try:
        resp = requests.delete("http://127.0.0.1:8088/critical-resource", timeout=2)
        print(f"[Exp 1] Result: {resp.status_code}", flush=True)
    except Exception as e:
        print(f"[Exp 1] Caught exception: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    run()
