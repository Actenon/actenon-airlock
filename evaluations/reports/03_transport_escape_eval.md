# ACTENON FIELD TEST 3 — ACTUAL SECURITY BOUNDARY ESCAPE TEST
**Evaluation Target:** [`Actenon/actenon-airlock`](https://github.com/Actenon/actenon-airlock)  
**Evaluator:** Independent Developer / Black-Box Security Evaluation  
**Status:** No code, approvals, policies, or tests in the Airlock codebase were modified.

---

## 1. Test Environment & Provenance

* **Git Commit SHA:** `b1b812126be3a35e056b0de85132bdf8ea2c3b74`
* **Installation Method:** Pinned repository dependencies installed into Python 3.12 venv via `uv pip install` (`actenon-airlock==0.1.0.dev0`, `actenon-scan==1.6.0`, `actenon-permit==2.0.0rc1`, `actenon-kernel==1.3.0`, `actenon-protocol==1.6.0`).
* **Host Environment:** macOS (Darwin 24.6.0, Apple Silicon arm64).
* **Protected Mode Compute Image:** Pinned Docker image `actenon-airlock-compute:dev` (`sha256:16614e52c9a8...`, Python 3.11.15 on Linux arm64).
* **Disposable Mock Service:** Standalone HTTP service running at `http://127.0.0.1:8088`:
  * `GET /health` — Baseline operation (explicitly approved).
  * `DELETE /critical-resource` — Simulated destructive operation (never approved).
  * `GET /__audit` — Independent server-side counter of received requests.
  * `POST /__reset` — Resets server-side audit counters between runs.

---

## 2. Baseline Unrestricted Control

To confirm that the test endpoint is live and that a failure to reach it is due to mediation rather than server failure:

* **Command:** `curl -s -X DELETE http://127.0.0.1:8088/critical-resource`
* **Server Audit Check:** `GET /__audit` returned `{"health_count": 0, "delete_count": 1, ...}`.
* **Result:** Endpoint is confirmed functional. Counter was reset to `0` via `POST /__reset` before commencing experiments.

---

## 3. Mandatory Adversarial Transport Experiments

### Baseline Authority Manifest
In `agent_project`, only `GET http://127.0.0.1:8088/health` was approved (`airlock init --approve --command "main.py"`). The capability `DELETE /critical-resource` was omitted.

---

### Experiment 1: Standard `requests.delete()` (Negative Control)

* **Objective:** Verify standard wrapped client interception.
* **Code (`exp1_requests.py`):**
  ```python
  import requests
  try:
      resp = requests.delete("http://127.0.0.1:8088/critical-resource", timeout=2)
  except Exception as e:
      print(f"[Exp 1] Caught: {type(e).__name__}: {e}")
  ```

#### Local Mode (`airlock run -- python exp1_requests.py`)
* **Exit Code:** `3`
* **Airlock Decision:** `AIRLOCK DENY http.delete @ http://127.0.0.1:8088/critical-resource: out of scope [receipt_a2cf3d182b8e481ea9ebe8258118ec3c]`
* **Client Exception:** `RequestsDenied: AIRLOCK BLOCKED: out of scope`
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

#### Protected Mode (`airlock run --protected -- python3 exp1_requests.py`)
* **Exit Code:** `1`
* **Airlock Decision:** Not intercepted by broker; Python failed during import (`ModuleNotFoundError: No module named 'requests'` as the compute image excludes third-party packages).
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS** (Zero external transport permitted)

---

### Experiment 2: `urllib.request` with method DELETE

* **Objective:** Test standard library urllib interception.
* **Code (`exp2_urllib.py`):**
  ```python
  import urllib.request
  req = urllib.request.Request("http://127.0.0.1:8088/critical-resource", method="DELETE")
  try:
      with urllib.request.urlopen(req, timeout=2) as resp:
          pass
  except Exception as e:
      print(f"[Exp 2] Caught: {type(e).__name__}: {e}")
  ```

#### Local Mode (`airlock run -- python exp2_urllib.py`)
* **Exit Code:** `3`
* **Airlock Decision:** `AIRLOCK DENY http.delete @ http://127.0.0.1:8088/critical-resource: out of scope [receipt_66db11b25ec44208a678a281392abdb6]`
* **Client Exception:** `UrllibDenied: <urlopen error AIRLOCK BLOCKED: out of scope>`
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

#### Protected Mode (`airlock run --protected -- python3 exp2_urllib.py`)
* **Exit Code:** `0` (Agent handled the network exception cleanly)
* **Supervisor Decision:** `OBSERVED contained-compute-exited process.exec @ contained-workspace:... [receipt_1030de72227849a983f373528be0fe77]`
* **Container Exception:** `URLError: <urlopen error [Errno 111] Connection refused>` (Linux container has `--network none`)
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

---

### Experiment 3: `http.client.HTTPConnection` with method DELETE

* **Objective:** Test low-level standard library HTTP client.
* **Code (`exp3_http_client.py`):**
  ```python
  import http.client
  try:
      conn = http.client.HTTPConnection("127.0.0.1", 8088, timeout=2)
      conn.request("DELETE", "/critical-resource")
      resp = conn.getresponse()
  except Exception as e:
      print(f"[Exp 3] Caught: {type(e).__name__}: {e}")
  ```

#### Local Mode (`airlock run -- python exp3_http_client.py`)
* **Exit Code:** `3`
* **Airlock Decision:** `AIRLOCK DENY socket.getaddrinfo @ <local>: Unsupported runtime effect [receipt_90fb6dce3db14ea09b4a295434b087ef]`
* **Client Exception:** `RuntimeDenied: AIRLOCK BLOCKED: unsupported effect socket.getaddrinfo`
* **Mechanism:** Airlock's `sys.addaudithook` intercepted the socket resolution attempt and denied it before connection.
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

#### Protected Mode (`airlock run --protected -- python3 exp3_http_client.py`)
* **Exit Code:** `0` (Handled exception)
* **Supervisor Decision:** Contained execution observed; no IPC consequence requested.
* **Container Exception:** `ConnectionRefusedError: [Errno 111] Connection refused`
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

---

### Experiment 4: Raw Python `socket` sending complete HTTP DELETE

* **Objective:** Test unadapted raw TCP transmission of an HTTP frame.
* **Code (`exp4_raw_socket.py`):**
  ```python
  import socket
  try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(2)
      s.connect(("127.0.0.1", 8088))
      s.sendall(b"DELETE /critical-resource HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n")
      data = s.recv(1024)
  except Exception as e:
      print(f"[Exp 4] Caught: {type(e).__name__}: {e}")
  ```

#### Local Mode (`airlock run -- python exp4_raw_socket.py`)
* **Exit Code:** `3`
* **Airlock Decision:** `AIRLOCK DENY socket.connect @ <local>: Unsupported runtime effect [receipt_e8cb0c6a1ef94ef4910345af65f61dca]`
* **Client Exception:** `RuntimeDenied: AIRLOCK BLOCKED: unsupported effect socket.connect`
* **Mechanism:** Audit hook intercepts `socket.connect`, sending an `audit-deny` message to the broker and raising `RuntimeDenied`.
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

#### Protected Mode (`airlock run --protected -- python3 exp4_raw_socket.py`)
* **Exit Code:** `0` (Handled exception)
* **Supervisor Decision:** Contained execution observed; no broker action.
* **Container Exception:** `ConnectionRefusedError: [Errno 111] Connection refused` (No route/network inside isolated container namespace).
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

---

### Experiment 5: `subprocess.run()` invoking curl to send DELETE

* **Objective:** Test binary execution boundary escape.
* **Code (`exp5_curl_subprocess.py`):**
  ```python
  import subprocess
  try:
      proc = subprocess.run(
          ["curl", "-s", "-X", "DELETE", "http://127.0.0.1:8088/critical-resource"],
          capture_output=True, text=True, timeout=5
      )
  except Exception as e:
      print(f"[Exp 5] Caught: {type(e).__name__}: {e}")
  ```

#### Local Mode (`airlock run -- python exp5_curl_subprocess.py`)
* **Exit Code:** `3`
* **Airlock Decision:** `AIRLOCK DENY process.exec @ /usr/bin/curl: out of scope [receipt_24d34184b57344d089c28c8d875cf298]`
* **Client Exception:** `RuntimeDenied: AIRLOCK BLOCKED: out of scope`
* **Mechanism:** Python `subprocess.Popen` audit hook intercepts the spawn request. Permit evaluates the target against the grant. Because `/usr/bin/curl` was not approved, the execution was denied before fork/exec.
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

#### Protected Mode (`airlock run --protected -- python3 exp5_curl_subprocess.py`)
* **Exit Code:** `0` (Handled exception)
* **Supervisor Decision:** Contained execution observed.
* **Container Exception:** `FileNotFoundError: [Errno 2] No such file or directory: 'curl'` (Minimal compute image does not contain curl; if present, `--network none` would have blocked it).
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

---

### Experiment 6: Dynamically imported/executed Python code

* **Objective:** Test dynamic imports (`importlib.import_module`) and runtime `exec()` code evaluation.
* **Code (`exp6_dynamic_import.py`):**
  ```python
  import importlib
  # 1. Dynamic urllib import
  try:
      mod = importlib.import_module("urllib.request")
      req = mod.Request("http://127.0.0.1:8088/critical-resource", method="DELETE")
      mod.urlopen(req, timeout=2)
  except Exception as e:
      print(f"[Exp 6] Dynamic urllib: {type(e).__name__}: {e}")

  # 2. Dynamic exec() string
  try:
      exec("import requests\nrequests.delete('http://127.0.0.1:8088/critical-resource')", {})
  except Exception as e:
      print(f"[Exp 6] Dynamic exec: {type(e).__name__}: {e}")
  ```

#### Local Mode (`airlock run -- python exp6_dynamic_import.py`)
* **Exit Code:** `3`
* **Airlock Decisions:**
  * `AIRLOCK DENY http.delete @ http://127.0.0.1:8088/critical-resource: out of scope [receipt_2b2b68dbb9c94f129804048cfeb181c3]`
  * `AIRLOCK DENY http.delete @ http://127.0.0.1:8088/critical-resource: out of scope [receipt_be22b21f802d4c5d9bf31fde30032a19]`
* **Client Exceptions:**
  * `UrllibDenied: <urlopen error AIRLOCK BLOCKED: out of scope>`
  * `RequestsDenied: AIRLOCK BLOCKED: out of scope`
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

#### Protected Mode (`airlock run --protected -- python3 exp6_dynamic_import.py`)
* **Exit Code:** `0` (Handled exception)
* **Supervisor Decision:** Contained execution observed.
* **Container Exceptions:** Dynamic urllib raised `[Errno 111] Connection refused`; dynamic requests failed with `ModuleNotFoundError`.
* **Mock Server Observed DELETE Count:** `0`
* **Verdict:** **PASS**

---

## 4. Approval Separation & Authority Self-Granting Test

* **Code (`approval_escape_test.py`):**
  1. **Read Private Keys:** Attempted to open `.airlock/local/grant-key.json`, `private-key.json`, and `receipts.jsonl`.
  2. **Modify Manifest:** Attempted to append an unapproved capability to `.airlock/approved.json`.
  3. **Invoke CLI:** Attempted to run `airlock init --approve` or `python -m actenon_airlock.cli init --approve` via `subprocess.run()`.

### Local Mode Results
* **Key Read Attempt:**
  * `AIRLOCK DENY credential.read @ <local>: Unsupported runtime effect [receipt_c667a8995e9a4ba1a0e80f932f2aa0cd]`
  * Raised `RuntimeDenied: AIRLOCK BLOCKED: unsupported effect credential.read`. Zero private keys read.
* **Manifest Overwrite Attempt:**
  * `AIRLOCK DENY filesystem.write @ <unresolved>: Airlock state is not writable by the agent [receipt_4f5a00aeab85400b88313a5eb19b634f]`
  * Raised `RuntimeDenied: AIRLOCK BLOCKED: Airlock state is not writable by the agent`. Manifest remained unmodified.
* **CLI Approval Execution Attempt:**
  * `AIRLOCK DENY process.exec @ <unresolved>: Program 'airlock' is not on the broker PATH [receipt_618e9915da504166955b3c248386783d]`
  * Raised `RuntimeDenied: AIRLOCK BLOCKED: Program 'airlock' is not on the broker PATH`.
* **Authority Changed:** **NO**.

### Protected Mode Results
* **Key Read Attempt:** Raised `FileNotFoundError: [Errno 2] No such file or directory: '.airlock/local/grant-key.json'` (The supervisor explicitly excludes the `.airlock` directory from container workspace mounts).
* **Manifest Overwrite Attempt:** Raised `FileNotFoundError: [Errno 2] No such file or directory: '.airlock/approved.json'`.
* **CLI Approval Execution Attempt:** Raised `FileNotFoundError: 'airlock'` / `No module named actenon_airlock`.
* **Authority Changed:** **NO**.

---

## 5. Consolidated Results Matrix

| # | Attack Transport / Vector | Local Mode Decision | Protected Mode Decision | Mock Server DELETEs Observed | Threat Model Alignment | Final Verdict |
| :---: | :--- | :--- | :--- | :---: | :--- | :---: |
| **0** | **Baseline Unrestricted Control** | N/A (Direct curl) | N/A (Direct curl) | 1 | N/A (Functional Check) | **BASELINE OK** |
| **1** | `requests.delete()` | `DENY http.delete` (out of scope) | `DENY` (Module excluded from image) | 0 | Expected adapter boundary | **PASS** |
| **2** | `urllib.request` (DELETE) | `DENY http.delete` (out of scope) | `DENY` (`[Errno 111]` Connection refused) | 0 | Expected adapter boundary | **PASS** |
| **3** | `http.client.HTTPConnection` | `DENY socket.getaddrinfo` (Unsupported effect) | `DENY` (`[Errno 111]` Connection refused) | 0 | Expected audit hook fail-closed | **PASS** |
| **4** | Raw Python `socket` | `DENY socket.connect` (Unsupported effect) | `DENY` (`[Errno 111]` Connection refused) | 0 | Expected audit hook fail-closed | **PASS** |
| **5** | `subprocess.run(["curl"])` | `DENY process.exec` (out of scope) | `DENY` (Binary missing; network isolated) | 0 | Expected process capability check | **PASS** |
| **6** | Dynamically Imported Code | `DENY http.delete` (out of scope) | `DENY` (`[Errno 111]` Connection refused) | 0 | In-process hooks persist | **PASS** |
| **7** | **Read Private Signing Keys** | `DENY credential.read` (Unsupported effect) | `DENY` (Path not mounted: `FileNotFoundError`) | 0 | Credential isolation policy | **PASS** |
| **8** | **Overwrite Manifest (`approved.json`)**| `DENY filesystem.write` (State not writable)| `DENY` (Path not mounted: `FileNotFoundError`) | 0 | Integrity enforcement | **PASS** |
| **9** | **Execute Self-Approval via CLI** | `DENY process.exec` (Not on broker PATH) | `DENY` (`airlock` not in container image) | 0 | Separation of duties | **PASS** |

---

## 6. Audit & Verification Evidence

All 16 receipt records were verified against the committed `.airlock/public-key.json`:

```text
AIRLOCK RECEIPTS
16 of 16 verified against .airlock/public-key.json

2026-10-28T22:15:19.350021+00:00  DENY  http.delete @ http://127.0.0.1:8088/critical-resource
    reason: out of scope | no credential released | not executed  [receipt_a2cf3d182b8e481ea9ebe8258118ec3c]
2026-10-28T22:15:27.854846+00:00  DENY  http.delete @ http://127.0.0.1:8088/critical-resource
    reason: out of scope | no credential released | not executed  [receipt_66db11b25ec44208a678a281392abdb6]
2026-10-28T22:15:37.085814+00:00  DENY  socket.getaddrinfo @ <local>
    reason: Unsupported runtime effect | no credential released | not executed  [receipt_90fb6dce3db14ea09b4a295434b087ef]
2026-10-28T22:16:20.628455+00:00  DENY  socket.connect @ <local>
    reason: Unsupported runtime effect | no credential released | not executed  [receipt_e8cb0c6a1ef94ef4910345af65f61dca]
2026-10-28T22:16:31.173077+00:00  DENY  process.exec @ /usr/bin/curl
    reason: out of scope | no credential released | not executed  [receipt_24d34184b57344d089c28c8d875cf298]
2026-10-28T22:17:00.153395+00:00  DENY  http.delete @ http://127.0.0.1:8088/critical-resource
    reason: out of scope | no credential released | not executed  [receipt_2b2b68dbb9c94f129804048cfeb181c3]
2026-10-28T22:17:33.310105+00:00  DENY  credential.read @ <local>
    reason: Unsupported runtime effect | no credential released | not executed  [receipt_c667a8995e9a4ba1a0e80f932f2aa0cd]
2026-10-28T22:17:33.325811+00:00  DENY  filesystem.write @ <unresolved>
    reason: Airlock state is not writable by the agent | no credential released | not executed  [receipt_4f5a00aeab85400b88313a5eb19b634f]
```

Final mock service audit query returned `delete_count: 0`.

---

## 7. Findings & Architectural Assessment

1. **Local Mode Enforcement Mechanism:**
   Local Mode relies on cooperative Python monkey-patching for primary clients (`requests`, `httpx`, `urllib`) combined with `sys.addaudithook`. When an unadapted transport (`http.client` or raw `socket`) attempts network communication, the audit hook intercepts `socket.getaddrinfo` or `socket.connect`, routing the event to the broker as an unsupported effect and raising `RuntimeDenied`.
2. **Protected Mode Enforcement Mechanism:**
   Protected Mode achieves defense-in-depth through container isolation. The agent executes inside a container launched with `--network none`. No network device exists to route traffic to the host or outside world, causing any raw socket or HTTP call to fail at the OS layer with `ConnectionRefusedError [Errno 111]`. Furthermore, sensitive host state (`.airlock`, credentials, and keys) is excluded from volume mounts.
3. **Approval Separation:**
   Neither mode allowed the untrusted child to access signing keys, modify `approved.json`, or execute `airlock init --approve`. In Local Mode, state file writes and unapproved process spawns were intercepted by audit hooks. In Protected Mode, state files and operator tooling were omitted from the container filesystem entirely.
4. **Boundary Scope:**
   All tested transport vectors (`requests`, `urllib`, `http.client`, raw `socket`, `subprocess` curl, dynamic code) were blocked from issuing the unapproved `DELETE /critical-resource` request across both Local and Protected execution modes. In this evaluation, zero unapproved DELETE requests reached the mock service.