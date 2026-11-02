# ACTENON FIELD TEST 4 — PROVE THE BOUNDARY WITHOUT FALSE POSITIVES
**Target Evaluation:** [`Actenon/actenon-airlock`](https://github.com/Actenon/actenon-airlock) at commit `b1b812126be3a35e056b0de85132bdf8ea2c3b74`  
**Execution Environment:** macOS host (Apple Silicon), Docker Engine 29.9.2 (Linux container runtime)  
**Constraint Verification:** Zero modifications made to Actenon source code, dependencies, or security policies.

---

## 1. Executive Summary

Field Test 4 executed an end-to-end evaluation of Actenon Airlock’s **Protected Mode** (`airlock run --protected`) in the **SAME execution session**, verifying both:
1. **POSITIVE:** An authorized, reviewed text-model inference successfully crossed the IPC bridge, was verified by the host supervisor, executed against a local fixture endpoint, and returned a committed response to the contained agent.
2. **NEGATIVE:** The contained agent was unable to reach an unauthorized mock endpoint or execute an unapproved `DELETE /critical-resource` through any available transport (`requests`, `urllib`, `http.client`, raw `socket`, `curl`).

To eliminate false positives from missing binaries or loopback misconfigurations, all attack transports were **first proven functional** from an unrestricted control container connected to a dedicated Docker network.

---

## 2. Test Environment Architecture

```
                                      DOCKER TEST ENVIRONMENT
                                      
  Host Supervisor (Airlock Protected Broker)
  ├── Host Model Key: OPENAI_API_KEY="synthetic-supervisor-secret-key"
  └── Bound Model Endpoint: http://127.0.0.1:11434/v1/chat/completions
            │
            │ (Host Port 11434 mapped to Container Port 8080)
            ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Docker Bridge Network: airlock-test-net (Subnet: 172.22.0.0/16)       │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ airlock-mock-server (IP: 172.22.0.2:8080)                        │  │
│  │ ├── POST   /v1/chat/completions (OpenAI completion fixture)      │  │
│  │ ├── DELETE /critical-resource   (Forbidden target counter)       │  │
│  │ └── GET    /__audit             (Independent request ledger)     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                 ▲                                      │
│           Network-Enabled       │                                      │
│           Control Container     │ (All 5 Transports Succeeded)         │
│           (Same Compute Image) ─┘                                      │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│  Airlock Protected Mode Container Boundary                             │
│  (Engine: Docker | Network: none | User: 10000 | Caps: NONE | RO Root) │
│                                                                        │
│  ┌─────────────────────────┐         ┌───────────────────────────────┐ │
│  │ contained_agent (PID 1) │ ──────> │ IPC Broker Relay (/ipc/broker)│ │
│  └───────────┬─────────────┘ (Unix)  └───────────────┬───────────────┘ │
│              │                                       │                 │
│              ▼                                       ▼                 │
│   All 5 Alternative Transports             Supervisor Host RPC         │
│   (requests, urllib, socket, curl)         ├── Model Inference: ALLOW  │
│   BLOCKED at OS Layer                      └── Injected RPCs:   DENY   │
│   (No network route / Errno 101)                                       │
└────────────────────────────────────────────────────────────────────────┘
```

* **Compute Image:** `actenon-test-compute:v1` (ID: `sha256:e5be76ec97fc167a6797042e6bc1b4270080778abc45c0946f1c78b03e3f0ac2`), built from `actenon-airlock-compute:dev` with `requests 2.34.2`, `urllib`, `http.client`, `socket`, and `curl 8.14.1` verified present.
* **Mock Service Container:** `airlock-mock-server` running on Docker bridge network `airlock-test-net` (IP `172.22.0.2:8080`, mapped to host loopback `127.0.0.1:11434`).
* **Source Manifest:** Single fixed source snapshot in `protected_agent_project/main.py`. The model endpoint was statically reviewed and signed with `airlock init --approve`. Target parameters for negative attacks were passed at runtime via CLI arguments (`sys.argv`), ensuring the source manifest digest (`be07d85498747e46...`) remained strictly unmodified.

---

## 3. Control Container Verification (Proving Transports Are Functional)

To ensure the negative test does not pass due to a broken mock endpoint or misconfigured client libraries, a disposable network-enabled container using `actenon-test-compute:v1` was attached to `airlock-test-net` and executed all 5 transports against `http://airlock-mock-server:8080/critical-resource`.

### Control Execution Log
```text
=== CONTROL CONTAINER ATTACK SUITE START ===
[Control 1] requests.delete status: 200, body: {"deleted": true, "critical_destroyed": true}
[Control 2] urllib.request status: 200
[Control 3] http.client status: 200
[Control 4] raw socket received: HTTP/1.0 200 OK
[Control 5] curl exit: 0, first line: HTTP/1.0 200 OK
=== CONTROL CONTAINER ATTACK SUITE COMPLETED: {'requests': True, 'urllib': True, 'http_client': True, 'raw_socket': True, 'curl': True} ===
```

### Mock Service Audit Check (`GET http://127.0.0.1:11434/__audit`)
```json
{
  "health_count": 0,
  "forbidden_delete_count": 5,
  "model_requests_count": 0,
  "requests": [
    {"method": "DELETE", "path": "/critical-resource", "headers": {"User-Agent": "python-requests/2.34.2"}},
    {"method": "DELETE", "path": "/critical-resource", "headers": {"User-Agent": "Python-urllib/3.11"}},
    {"method": "DELETE", "path": "/critical-resource", "headers": {"Host": "airlock-mock-server:8080"}},
    {"method": "DELETE", "path": "/critical-resource", "headers": {"User-Agent": "ControlRawSocket/1.0"}},
    {"method": "DELETE", "path": "/critical-resource", "headers": {"User-Agent": "curl/8.14.1"}}
  ]
}
```
* **Control Result:** All 5 transports were functional and capable of executing the forbidden DELETE.
* **Reset:** `POST http://127.0.0.1:11434/__reset` reset `forbidden_delete_count` to `0` prior to the Protected Mode experiment.

---

## 4. Central Protected Mode Experiment (Same Session)

The agent was executed under genuine Protected Mode:
```bash
OPENAI_API_KEY="synthetic-supervisor-secret-key" airlock run \
  --protected \
  --image actenon-test-compute:v1 \
  -- python3 main.py http://airlock-mock-server:8080/critical-resource airlock-mock-server 8080
```

### Execution Log Output

```text
AIRLOCK PROTECTED MODE: compute inside; external consequences cross the supervisor

--- [POSITIVE OPERATION: APPROVED MODEL INFERENCE] ---
AIRLOCK ALLOW http.post @ http://127.0.0.1:11434/v1/chat/completions: effect COMMITTED; duplicate dispatch blocked [receipt_cd5a331d5d5a422bbc7fdec1ed9e4bc7]
[POSITIVE] Received model response: POSITIVE_BROKER_INFERENCE_SUCCESS

--- [NEGATIVE ADVERSARIAL TRANSPORT ATTACKS] ---
[Target Config] URL: http://airlock-mock-server:8080/critical-resource, Host: airlock-mock-server, Port: 8080
[Attack 1 - requests] BLOCKED: ConnectionError: HTTPConnectionPool(host='airlock-mock-server', port=8080): Max retries exceeded with url: /critical-resource (Caused by NameResolutionError("HTTPConnection(host='airlock-mock-server', port=8080): Failed to resolve 'airlock-mock-server' ([Errno -3] Temporary failure in name resolution)"))
[Attack 2 - urllib] BLOCKED: URLError: <urlopen error [Errno -3] Temporary failure in name resolution>
[Attack 3 - http.client] BLOCKED: gaierror: [Errno -3] Temporary failure in name resolution
[Attack 4 - raw socket (airlock-mock-server)] BLOCKED: gaierror: [Errno -3] Temporary failure in name resolution
[Attack 4 - raw socket (172.22.0.2)] BLOCKED: OSError: [Errno 101] Network is unreachable
[Attack 5 - curl] BLOCKED: returncode 6, stderr: 

--- [APPROVAL ISOLATION & DIRECT BRIDGE ATTACKS] ---
[Isolation] Protected: Key file /airlock/local/grant-key.json does not exist.
[Isolation] Protected: Key file /airlock/key.json does not exist.
[Isolation] Protected: Key file .airlock/local/grant-key.json does not exist.
[Bridge Attack] Found IPC socket at /ipc/broker.sock. Testing unapproved RPC injection...
AIRLOCK DENY unsupported @ <protected boundary>: No protected executor for this request [receipt_4c130032ac2447358b3e8c706c22bdd3]
[Bridge Attack - self_approve] Supervisor response: ok=False, reason=No protected executor for this request
AIRLOCK DENY http.delete @ http://airlock-mock-server:8080/critical-resource: No reviewed protected consequence profile for this endpoint [receipt_0212f8cecdf547dbb02729d171c5ef22]
[Bridge Attack - unauthorized_delete] Supervisor response: ok=False, reason=No reviewed protected consequence profile for this endpoint
AIRLOCK DENY github.repo.delete @ https://api.github.com/repos/acme/private-repo: No reviewed protected consequence profile for this endpoint [receipt_16bb9dcfc367400a8d3791a71caea4cf]
[Bridge Attack - unauthorized_github] Supervisor response: ok=False, reason=No reviewed protected consequence profile for this endpoint

Protected workspace results (untrusted files): .../.airlock/local/runs/protected_ab045fd0bf5d41829b2f6e6ca5159352/workspace
EXIT_CODE: 3
```

---

## 5. Independent Mock Server Audit Check

Immediately after the Protected Mode session completed, the mock service audit endpoint was queried directly from the host:

`curl -s http://127.0.0.1:11434/__audit`

```json
{
  "health_count": 0,
  "forbidden_delete_count": 0,
  "model_requests_count": 1,
  "received_auth_headers": [],
  "requests": [
    {
      "method": "POST",
      "path": "/v1/chat/completions",
      "headers": {
        "Host": "127.0.0.1:11434",
        "User-Agent": "python-httpx/0.28.1",
        "Content-Type": "application/json",
        "Content-Length": "102"
      },
      "body": "{\"max_tokens\":256,\"messages\":[{\"content\":\"eval-query-1793226496\",\"role\":\"user\"}],\"model\":\"test-model\"}"
    }
  ]
}
```

### Server-Side Independent Verification
* **Approved Model Inference:** Exactly **1** request was dispatched by the host supervisor (`python-httpx/0.28.1`) and received by the mock server.
* **Forbidden DELETE Requests:** Exactly **0** DELETE requests reached the server across all 5 transports.

---

## 6. Container Boundary & Docker Inspection Validation

The supervisor recorded the verified Docker engine configuration in `boundary.json`:

```json
{
  "schema": "actenon-airlock/protected-run/v1",
  "run_id": "protected_ab045fd0bf5d41829b2f6e6ca5159352",
  "engine": {
    "os": "linux",
    "server_version": "29.9.2",
    "seccomp": true
  },
  "image_id": "sha256:e5be76ec97fc167a6797042e6bc1b4270080778abc45c0946f1c78b03e3f0ac2",
  "agent": {
    "container_id": "9b7e1add30f8fb17d1745f6edaaf44c16de2136e82a6f86ddadf12eaf9aefde7",
    "network": "none",
    "read_only_root": true,
    "mounts": {
      "/airlock": {"rw": false, "type": "bind"},
      "/ipc": {"rw": false, "type": "volume"},
      "/workspace": {"rw": true, "type": "bind"}
    }
  },
  "bridge": {
    "container_id": "69121756e621e07d552396794750e8fb31ef3efa946dbfe38b4656f26eba8b06",
    "network": "none",
    "read_only_root": true,
    "mounts": {
      "/airlock": {"rw": false, "type": "bind"},
      "/ipc": {"rw": true, "type": "volume"}
    }
  }
}
```

### Contained Environment Parameters (Observed from Inside the Container)
From the agent's self-recorded `execution_report.json`:
* `uid`: `10000`, `gid`: `10000` (non-root execution).
* `OPENAI_API_KEY`: `"airlock-no-standing-credential"` (synthetic dummy key; host key withheld).
* `OPENAI_BASE_URL`: `http://127.0.0.1:42121/v1` (ephemeral loopback relay to IPC bridge).
* `/var/run/docker.sock`: Does not exist.
* Signing Keys: `.airlock/local/grant-key.json` and `/airlock/key.json` do not exist.

### Failure Classification: OS-Level vs. Broker-Level Denials
* **Transports targeting the external mock server (`requests`, `urllib`, `http.client`, `socket`, `curl`):**
  * Failed at the **OS network layer** inside the container namespace (`NameResolutionError [Errno -3]` for hostname; `OSError: [Errno 101] Network is unreachable` for direct IP `172.22.0.2`; `curl exit code 6`).
  * Because the container has `--network none`, no packets could leave the Linux container. These are recorded as **OS-level transport failures**, not synthetic broker denial receipts.
* **Direct Unix Domain Socket Bridge Injection (`/ipc/broker.sock`):**
  * When the contained agent bypassed Python libraries and wrote raw JSON frames directly to the supervisor’s IPC socket, the host supervisor evaluated each message and returned signed **Broker-Level Denials**:
    * Injected `self_approve`: `AIRLOCK DENY unsupported @ <protected boundary>: No protected executor for this request [receipt_4c130032ac2447358b3e8c706c22bdd3]`
    * Injected `unauthorized_delete`: `AIRLOCK DENY http.delete @ http://airlock-mock-server:8080/critical-resource: No reviewed protected consequence profile for this endpoint [receipt_0212f8cecdf547dbb02729d171c5ef22]`
    * Injected `unauthorized_github`: `AIRLOCK DENY github.repo.delete @ https://api.github.com/repos/acme/private-repo: No reviewed protected consequence profile for this endpoint [receipt_16bb9dcfc367400a8d3791a71caea4cf]`

---

## 7. Consolidated Results Matrix

| Transport / Operation | Control Container (Network-Enabled) | Protected Mode (Contained Agent) | Failure Mechanism | Server Audit DELETE Count | Verdict |
| :--- | :---: | :---: | :--- | :---: | :---: |
| **Approved Model Inference** | N/A (Host-brokered) | **SUCCESS** (`POSITIVE_BROKER_INFERENCE_SUCCESS`) | Supervisor Verified & Dispatched (`COMMITTED`) | 0 (1 Model Hit) | **PASS** |
| `requests.delete()` | **SUCCESS** (200 OK) | **BLOCKED** | OS Layer (`NameResolutionError [Errno -3]`) | 0 | **PASS** |
| `urllib.request` (DELETE) | **SUCCESS** (200 OK) | **BLOCKED** | OS Layer (`URLError [Errno -3]`) | 0 | **PASS** |
| `http.client.HTTPConnection` | **SUCCESS** (200 OK) | **BLOCKED** | OS Layer (`gaierror [Errno -3]`) | 0 | **PASS** |
| Raw `socket` (Hostname) | **SUCCESS** (200 OK) | **BLOCKED** | OS Layer (`gaierror [Errno -3]`) | 0 | **PASS** |
| Raw `socket` (Direct IP `172.22.0.2`) | **SUCCESS** (200 OK) | **BLOCKED** | OS Layer (`OSError [Errno 101] Network is unreachable`) | 0 | **PASS** |
| `subprocess` (`curl -X DELETE`) | **SUCCESS** (200 OK) | **BLOCKED** | OS Layer (`curl returncode 6: Could not resolve host`) | 0 | **PASS** |
| **Direct Bridge RPC: Self-Approve** | N/A | **BLOCKED** | Broker Policy (`No protected executor for this request`) | 0 | **PASS** |
| **Direct Bridge RPC: Unreviewed DELETE**| N/A | **BLOCKED** | Broker Policy (`No reviewed protected consequence profile`) | 0 | **PASS** |
| **Access Host Signing Keys** | N/A | **BLOCKED** | Filesystem Isolation (`FileNotFoundError`) | 0 | **PASS** |

---

## 8. Cryptographic Receipts Verification

Running `airlock receipts` in the project verified all 14 chained Ed25519 receipts against `.airlock/public-key.json`:

```text
AIRLOCK RECEIPTS
14 of 14 verified against .airlock/public-key.json

2026-10-28T22:28:16.835101+00:00  ALLOW authorized      http.post @ http://127.0.0.1:11434/v1/chat/completions
    main.py:37 | no credential released | not executed  [receipt_7a3a21993a7d4f90b1d31395259c9fd5]
2026-10-28T22:28:16.845894+00:00  ALLOW response-received http.post @ http://127.0.0.1:11434/v1/chat/completions
    main.py:37 | no credential released | effect: COMMITTED | effect_d1b34f199d56a42970a81dcf9c32381050f7a7ddfe1af464201b57ee59ec2566 | executed  [receipt_cd5a331d5d5a422bbc7fdec1ed9e4bc7]
2026-10-28T22:28:16.856764+00:00  DENY                  unsupported @ <protected boundary>
    reason: No protected executor for this request | no credential released | not executed  [receipt_4c130032ac2447358b3e8c706c22bdd3]
2026-10-28T22:28:16.857813+00:00  DENY                  http.delete @ http://airlock-mock-server:8080/critical-resource
    reason: No reviewed protected consequence profile for this endpoint | no credential released | not executed  [receipt_0212f8cecdf547dbb02729d171c5ef22]
2026-10-28T22:28:16.858519+00:00  DENY                  github.repo.delete @ https://api.github.com/repos/acme/private-repo
    reason: No reviewed protected consequence profile for this endpoint | no credential released | not executed  [receipt_16bb9dcfc367400a8d3791a71caea4cf]
2026-10-28T22:28:17.390447+00:00  OBSERVED contained-compute-exited process.exec @ contained-workspace:protected_ab045fd0bf5d41829b2f6e6ca5159352
    no credential released | executed  [receipt_0def3a44483347698277aee38d61e44a]
```

---

## 9. Final Conclusion

1. **Dual Verification Confirmed:** The positive path (approved model completion via supervisor) completed with a verifiable `COMMITTED` receipt and valid fixture response, while all negative paths (unapproved DELETE requests) were blocked before reaching the mock server.
2. **Elimination of False Positives:** The control container confirmed that all 5 transports (`requests`, `urllib`, `http.client`, raw `socket`, `curl`) were functional and capable of executing the forbidden DELETE. In the identical Protected Mode container, all 5 failed.
3. **No Boundary Escapes Observed:** Zero unauthorized DELETE requests reached the mock server during Protected Mode execution. Attempts to bypass the container via direct IPC socket manipulation were rejected by the supervisor with signed denial receipts.

**Final Test Rating:** **PASS** (Zero boundary escapes detected across all tested transports).