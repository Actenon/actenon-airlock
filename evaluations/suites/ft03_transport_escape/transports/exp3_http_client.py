"""Experiment 3: http.client.HTTPConnection with method DELETE"""
import http.client

def run():
    print("[Exp 3] Testing http.client.HTTPConnection with method DELETE...", flush=True)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 8088, timeout=2)
        conn.request("DELETE", "/critical-resource")
        resp = conn.getresponse()
        print(f"[Exp 3] Result: {resp.status}", flush=True)
    except Exception as e:
        print(f"[Exp 3] Caught exception: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    run()
