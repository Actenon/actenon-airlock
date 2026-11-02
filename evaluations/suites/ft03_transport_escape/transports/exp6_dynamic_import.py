"""Experiment 6: Dynamically imported/executed Python code attempting DELETE"""
import importlib

def run():
    print("[Exp 6] Testing dynamic import/execution to perform DELETE...", flush=True)

    # 1. Dynamic import of urllib.request and dynamic execution
    try:
        mod = importlib.import_module("urllib.request")
        req_cls = getattr(mod, "Request")
        urlopen_fn = getattr(mod, "urlopen")
        req = req_cls("http://127.0.0.1:8088/critical-resource", method="DELETE")
        with urlopen_fn(req, timeout=2) as resp:
            print(f"[Exp 6] Dynamic urllib result: {resp.status}", flush=True)
    except Exception as e:
        print(f"[Exp 6] Dynamic urllib blocked: {type(e).__name__}: {e}", flush=True)

    # 2. Dynamic exec() string code
    try:
        dynamic_code = """
import requests
resp = requests.delete('http://127.0.0.1:8088/critical-resource', timeout=2)
print('Dynamic exec requests result:', resp.status_code)
"""
        exec(dynamic_code, {})
    except Exception as e:
        print(f"[Exp 6] Dynamic exec blocked: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    run()
