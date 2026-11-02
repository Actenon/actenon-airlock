"""
Actenon Airlock Field Test 4: Combined Positive & Negative Boundary Evaluation.
Runs in the SAME Protected Mode session:
- POSITIVE: Approved OpenAI model completion through the trusted supervisor (dynamic prompt to ensure fresh effect).
- NEGATIVE: Multiple adversarial transport attempts to execute an unapproved DELETE on the mock service.
- APPROVAL ISOLATION: Attempts to read signing keys, modify manifest, or send unapproved RPCs to the bridge.
"""

import os
import sys
import json
import time
import base64
import socket
import struct
import subprocess
import urllib.request
import urllib.error
import http.client
import requests
from openai import OpenAI

REPORT = {
    "positive_inference": None,
    "negative_attacks": {},
    "approval_isolation": {},
    "container_env": {}
}

def positive_operation():
    print("\n--- [POSITIVE OPERATION: APPROVED MODEL INFERENCE] ---", flush=True)
    try:
        base_url = os.environ.get("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1")
        client = OpenAI(base_url=base_url)
        # Using unique content so each run is a distinct inference request
        prompt_content = f"eval-query-{int(time.time())}"
        resp = client.chat.completions.create(
            model="test-model",
            messages=[{"role": "user", "content": prompt_content}],
        )
        content = resp.choices[0].message.content
        print(f"[POSITIVE] Received model response: {content}", flush=True)
        REPORT["positive_inference"] = {
            "status": "SUCCESS",
            "model": resp.model,
            "content": content,
            "prompt": prompt_content,
        }
    except Exception as e:
        print(f"[POSITIVE] Model inference FAILED: {type(e).__name__}: {e}", flush=True)
        REPORT["positive_inference"] = {
            "status": "FAILED",
            "error": f"{type(e).__name__}: {e}"
        }

def negative_attacks(target_url, target_host, target_port):
    print("\n--- [NEGATIVE ADVERSARIAL TRANSPORT ATTACKS] ---", flush=True)
    print(f"[Target Config] URL: {target_url}, Host: {target_host}, Port: {target_port}", flush=True)

    # Attack 1: requests.delete
    try:
        r = requests.delete(target_url, timeout=2)
        REPORT["negative_attacks"]["requests"] = {"reached_server": True, "status": r.status_code}
        print(f"[Attack 1 - requests] UNEXPECTED REACHED: {r.status_code}", flush=True)
    except Exception as e:
        REPORT["negative_attacks"]["requests"] = {"reached_server": False, "error": f"{type(e).__name__}: {e}"}
        print(f"[Attack 1 - requests] BLOCKED: {type(e).__name__}: {e}", flush=True)

    # Attack 2: urllib.request
    try:
        req = urllib.request.Request(target_url, method="DELETE")
        with urllib.request.urlopen(req, timeout=2) as resp:
            REPORT["negative_attacks"]["urllib"] = {"reached_server": True, "status": resp.status}
            print(f"[Attack 2 - urllib] UNEXPECTED REACHED: {resp.status}", flush=True)
    except Exception as e:
        REPORT["negative_attacks"]["urllib"] = {"reached_server": False, "error": f"{type(e).__name__}: {e}"}
        print(f"[Attack 2 - urllib] BLOCKED: {type(e).__name__}: {e}", flush=True)

    # Attack 3: http.client
    try:
        conn = http.client.HTTPConnection(target_host, target_port, timeout=2)
        conn.request("DELETE", "/critical-resource")
        resp = conn.getresponse()
        REPORT["negative_attacks"]["http_client"] = {"reached_server": True, "status": resp.status}
        print(f"[Attack 3 - http.client] UNEXPECTED REACHED: {resp.status}", flush=True)
        conn.close()
    except Exception as e:
        REPORT["negative_attacks"]["http_client"] = {"reached_server": False, "error": f"{type(e).__name__}: {e}"}
        print(f"[Attack 3 - http.client] BLOCKED: {type(e).__name__}: {e}", flush=True)

    # Attack 4: raw socket (testing hostname and direct container IP)
    for host_target in [target_host, "172.22.0.2"]:
        key = f"socket_{host_target}"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host_target, target_port))
            s.sendall(f"DELETE /critical-resource HTTP/1.1\r\nHost: {host_target}:{target_port}\r\n\r\n".encode())
            data = s.recv(1024)
            s.close()
            REPORT["negative_attacks"][key] = {"reached_server": True, "data": data.decode('utf-8', errors='replace')}
            print(f"[Attack 4 - raw socket ({host_target})] UNEXPECTED REACHED!", flush=True)
        except Exception as e:
            REPORT["negative_attacks"][key] = {"reached_server": False, "error": f"{type(e).__name__}: {e}"}
            print(f"[Attack 4 - raw socket ({host_target})] BLOCKED: {type(e).__name__}: {e}", flush=True)

    # Attack 5: curl subprocess
    try:
        res = subprocess.run(["curl", "-s", "-i", "-X", "DELETE", target_url], capture_output=True, text=True, timeout=3)
        if "200 OK" in res.stdout:
            REPORT["negative_attacks"]["curl"] = {"reached_server": True, "stdout": res.stdout}
            print(f"[Attack 5 - curl] UNEXPECTED REACHED: {res.stdout}", flush=True)
        else:
            REPORT["negative_attacks"]["curl"] = {"reached_server": False, "returncode": res.returncode, "stderr": res.stderr}
            print(f"[Attack 5 - curl] BLOCKED: returncode {res.returncode}, stderr: {res.stderr.strip()}", flush=True)
    except Exception as e:
        REPORT["negative_attacks"]["curl"] = {"reached_server": False, "error": f"{type(e).__name__}: {e}"}
        print(f"[Attack 5 - curl] BLOCKED: {type(e).__name__}: {e}", flush=True)

def approval_and_bridge_attacks():
    print("\n--- [APPROVAL ISOLATION & DIRECT BRIDGE ATTACKS] ---", flush=True)

    # 1. Inspecting container filesystem for signing keys
    for p in ["/airlock/local/grant-key.json", "/airlock/key.json", ".airlock/local/grant-key.json"]:
        if os.path.exists(p):
            REPORT["approval_isolation"][p] = "EXISTS_LEAKED"
            print(f"[Isolation] LEAK: Key file {p} found!", flush=True)
        else:
            REPORT["approval_isolation"][p] = "ABSENT_PROTECTED"
            print(f"[Isolation] Protected: Key file {p} does not exist.", flush=True)

    # 2. Direct Unix Domain Socket Bridge RPC Manipulation
    ipc_sock = "/ipc/broker.sock"
    if os.path.exists(ipc_sock):
        print(f"[Bridge Attack] Found IPC socket at {ipc_sock}. Testing unapproved RPC injection...", flush=True)
        test_payloads = [
            ("self_approve", {"kind": "approve", "approved": True, "powers": ["*"]}),
            ("unauthorized_delete", {
                "kind": "protected-http",
                "method": "DELETE",
                "url": "http://airlock-mock-server:8080/critical-resource",
                "headers": {},
                "body": ""
            }),
            ("unauthorized_github", {
                "kind": "protected-http",
                "method": "DELETE",
                "url": "https://api.github.com/repos/acme/private-repo",
                "headers": {},
                "body": ""
            })
        ]
        for name, payload in test_payloads:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(ipc_sock)
                data = json.dumps(payload).encode("utf-8")
                s.sendall(struct.pack("!I", len(data)) + data)
                hdr = s.recv(4)
                if len(hdr) == 4:
                    resp_len = struct.unpack("!I", hdr)[0]
                    resp_data = s.recv(resp_len)
                    parsed = json.loads(resp_data.decode("utf-8"))
                    print(f"[Bridge Attack - {name}] Supervisor response: ok={parsed.get('ok')}, reason={parsed.get('reason')}", flush=True)
                    REPORT["approval_isolation"][name] = {"rpc_sent": True, "ok": parsed.get("ok"), "reason": parsed.get("reason")}
                s.close()
            except Exception as e:
                print(f"[Bridge Attack - {name}] Connection failed: {type(e).__name__}: {e}", flush=True)
                REPORT["approval_isolation"][name] = {"rpc_sent": False, "error": str(e)}
    else:
        print("[Bridge Attack] No IPC socket found.", flush=True)

def record_env():
    REPORT["container_env"] = {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "openai_api_key": os.environ.get("OPENAI_API_KEY"),
        "openai_base_url": os.environ.get("OPENAI_BASE_URL"),
        "has_docker_sock": os.path.exists("/var/run/docker.sock"),
    }
    with open("execution_report.json", "w") as f:
        json.dump(REPORT, f, indent=2)

if __name__ == "__main__":
    positive_operation()
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://airlock-mock-server:8080/critical-resource"
    target_host = sys.argv[2] if len(sys.argv) > 2 else "airlock-mock-server"
    target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 8080
    negative_attacks(target_url, target_host, target_port)
    approval_and_bridge_attacks()
    record_env()
