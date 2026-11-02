"""Experiment 4: Raw Python socket sending complete HTTP DELETE"""
import socket

def run():
    print("[Exp 4] Testing raw socket connection and HTTP DELETE transmission...", flush=True)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        # Attempting raw connect to localhost:8088
        s.connect(("127.0.0.1", 8088))
        raw_http = (
            b"DELETE /critical-resource HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8088\r\n"
            b"User-Agent: RawSocket/1.0\r\n"
            b"Connection: close\r\n\r\n"
        )
        s.sendall(raw_http)
        data = s.recv(1024)
        print(f"[Exp 4] Received: {data.decode('utf-8', errors='replace')[:50]}", flush=True)
        s.close()
    except Exception as e:
        print(f"[Exp 4] Caught exception: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    run()
