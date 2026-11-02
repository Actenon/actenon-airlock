### Developer Discovery & Hands-on Field Test: `actenon-airlock`

I discovered [**Actenon Airlock**](https://github.com/Actenon/actenon-airlock), a framework that claims to:
1. **Statically discover an AI agent's powers** (HTTP endpoints, process execution, filesystem operations) before launch.
2. **Block new or modified powers** until an engineer explicitly reviews and signs off (`airlock init --approve`).
3. **Intercept runtime actions at the Python layer**, refusing unapproved calls before they touch the network or OS.
4. **Reserve consequential effects** (POST/PUT/DELETE) to prevent blind duplicate retries across runs or network hiccups.
5. **Produce Ed25519-signed, hash-chained receipts** in `.airlock/local/receipts.jsonl`.

To test whether it actually solves the problems it claims to solve, I tested Airlock against a real-world scenario **without modifying any code in the Airlock codebase**.

---

### Test Setup: Real-World SRE Incident Triage Agent

I created an autonomous **SRE Incident Triage Agent** that interacts with an internal API:
* **Read-only query**: `GET http://127.0.0.1:9000/api/v1/health`
* **Consequential action**: `POST http://127.0.0.1:9000/api/v1/incidents/status` with incident triage metadata.
* **Mock Service**: A local server recording all incoming HTTP traffic (`GET /__requests`) to verify whether blocked actions actually stay off the wire.

Airlock was installed into an isolated Python 3.12 environment using its pinned dependencies (`actenon-scan 1.6.0`, `actenon-permit 2.0.0rc1`, `actenon-kernel 1.3.0`, `actenon-protocol 1.6.0`).

---

### Test Execution & Findings

```
                                  AIRLOCK LIFECYCLE
                                  
   Agent Source Code                Static Discovery                  Human Approval Gate
┌──────────────────────┐         ┌────────────────────┐         ┌───────────────────────────────┐
│   main.py (requests) │ ──────> │  actenon-scan AST  │ ──────> │  airlock init --approve       │
└──────────────────────┘         └────────────────────┘         │  (signs .airlock/approved.json│
                                                                └──────────────┬────────────────┘
                                                                               │
 ┌─────────────────────────────────────────────────────────────────────────────┘
 │
 ▼
Runtime Broker Execution (`airlock run`)
 ├── [GET  /health] ───────────────> [MATCHES APPROVED] ──────> Allowed (Executed)
 ├── [POST /incidents/status] ────> [MATCHES APPROVED] ──────> First Dispatch: Allowed (Held AMBIGUOUS)
 │                                                         └─> Duplicate Dispatch: DENIED (Already Reserved)
 ├── [DELETE /clusters/prod-db] ──> [UNAPPROVED POWER] ─────> DENIED (Out of Scope, Zero Network Traffic)
 └── [subprocess 'whoami'] ───────> [UNAPPROVED PROCESS] ───> DENIED (Blocked before OS execution)
```

---

#### 1. Discovery & Gating (`airlock init` & `airlock run`)
Before approval, running `airlock init` statically scanned `main.py` without executing it:

```text
AIRLOCK AUTHORITY DIFF

+ http.get @ 127.0.0.1:9000/api/v1/health
  Transport: http://127.0.0.1:9000/api/v1/health
  Scope: GET to exactly http://127.0.0.1:9000/api/v1/health
+ http.post @ 127.0.0.1:9000/api/v1/incidents/status
  Transport: http://127.0.0.1:9000/api/v1/incidents/status
  Scope: POST to exactly http://127.0.0.1:9000/api/v1/incidents/status

Runtime: BLOCKED UNTIL APPROVED
```

When running `airlock run` before approving:
* **Result**: Airlock refused launch immediately with exit code `2`:
  ```text
  AIRLOCK BLOCKED: No local approval; run airlock init --approve after review
  ```
* **Verdict**: **Passed**. New code cannot run until reviewed.

---

#### 2. Explicit Approval & Consequential Execution
Running `airlock init --approve` generated `.airlock/approved.json` containing an Ed25519 signature over the exact source AST digests and source line coordinates (`main.py:11`, `main.py:22`).

Running `airlock run`:
```text
[Agent] Checking system health...
AIRLOCK ALLOW http.get @ http://127.0.0.1:9000/api/v1/health [receipt_5358d061256247728df5893f51e0d40e]
[Agent] Health check status: {'status': 'healthy', 'version': '1.0.0'}
[Agent] Posting incident status update...
AIRLOCK ALLOW http.post @ http://127.0.0.1:9000/api/v1/incidents/status: effect AMBIGUOUS; duplicate dispatch blocked [receipt_32ac35c7f75644878c31b3c5ea34fca4]
[Agent] Consequential action dispatched: {'acknowledged': True, 'path': '/api/v1/incidents/status', ...}
```
* **Verdict**: **Passed**. Both calls completed as intended, and the consequential POST effect was held with state `AMBIGUOUS` (transport completed, remote commitment not assumed).

---

#### 3. Duplicate Consequential Action / Retry Protection
AI agents often retry actions blindly when a transient failure occurs. To test Airlock's effect reservation, I executed `airlock run` a second time with the exact same payload:

```text
[Agent] Checking system health...
AIRLOCK ALLOW http.get @ http://127.0.0.1:9000/api/v1/health [receipt_f8abde7954ef4af58f88d0edfd7d053e]
[Agent] Health check status: {'status': 'healthy', 'version': '1.0.0'}
[Agent] Posting incident status update...
AIRLOCK DENY http.post @ http://127.0.0.1:9000/api/v1/incidents/status: effect already reserved, committed, or unresolved [receipt_33fbc0266d194948a6d5b22bd366bdfa]
AIRLOCK BLOCKED: effect already reserved, committed, or unresolved
```

* **Server-side wire verification**: Queried `GET /__requests` on the mock service. The second POST **never hit the server**.
* **Reconciliation CLI**: Inspected the reservation with `airlock reconcile effect_3256b7c6ea...`:
  ```json
  {
    "action": "http.post",
    "target": "http://127.0.0.1:9000/api/v1/incidents/status",
    "prior_state": "AMBIGUOUS",
    "reservation_id": "reservation_301bee0f904843baac9f4b30db6ec783"
  }
  ```
* **Verdict**: **Passed**. Airlock protects non-idempotent consequential endpoints from uncoordinated retries.

---

#### 4. Privilege Creep & Destructive Action Interception
I updated `main.py` with an unapproved destructive call:
```python
requests.delete("http://127.0.0.1:9000/api/v1/clusters/prod-db")
```

1. **Static Authority Diff (`airlock diff`)**:
   ```text
   AIRLOCK AUTHORITY DIFF
   + http.delete @ 127.0.0.1:9000/api/v1/clusters/prod-db
     Transport: http://127.0.0.1:9000/api/v1/clusters/prod-db
     Scope: DELETE to exactly http://127.0.0.1:9000/api/v1/clusters/prod-db
   Runtime: BLOCKED UNTIL APPROVED
   ```
2. **CI Check (`airlock check`)**: Exited with code `2` (authority expansion detected).
3. **Runtime Protection (`airlock run`)**:
   ```text
   AIRLOCK: 1 new powers remain blocked
   [Agent] Checking system health...
   AIRLOCK ALLOW http.get @ http://127.0.0.1:9000/api/v1/health [receipt_...]
   [Agent] Attempting unauthorized destructive DELETE...
   AIRLOCK DENY http.delete @ http://127.0.0.1:9000/api/v1/clusters/prod-db: out of scope [receipt_5951b97714dd47e182daff0f9b462fe0]
   [Agent] DELETE failed: RequestsDenied: AIRLOCK BLOCKED: out of scope
   [Agent] Posting incident status update...
   AIRLOCK ALLOW http.post @ http://127.0.0.1:9000/api/v1/incidents/status [...]
   ```
* **Network verification**: Checked mock server logs. The `DELETE` request was **never transmitted across the network**. It was intercepted in-process before socket dispatch, raised `RequestsDenied` (which subclasses `requests.ConnectionError` and `PermissionError`), allowed standard agent error handling to catch it, and exited with code `3`.
* **Verdict**: **Passed**. Destructive unapproved actions are neutralized at runtime.

---

#### 5. Dynamic URLs & Process Execution Control
* **Dynamic Targets**: When the agent attempted a dynamically evaluated path `requests.get(f"http://127.0.0.1:9000/{runtime_path}")` pointing to `api/v1/unapproved_secrets`, Airlock denied the request (`AIRLOCK DENY: out of scope`).
* **Subprocess Execution**: Added `subprocess.run(["whoami"])` and `subprocess.run(["id"])`:
  * Airlock classified `whoami` as `process.exec @ whoami`.
  * Before approval, `whoami` was blocked with `AIRLOCK DENY process.exec @ /usr/bin/whoami: out of scope`.
  * After running `airlock init --approve`, `whoami` ran successfully.
  * When the code subsequently attempted `id`, Airlock allowed `whoami` and denied `id` (`AIRLOCK DENY process.exec @ /usr/bin/id: out of scope`).
* **Verdict**: **Passed**.

---

#### 6. Cryptographic Receipt Ledger (`airlock receipts`)
Ran `airlock receipts` to check the audit log:

```text
AIRLOCK RECEIPTS
31 of 31 verified against .airlock/public-key.json

2026-10-28T21:59:57.532322+00:00  ALLOW authorized      http.get @ http://127.0.0.1:9000/api/v1/health
2026-10-28T21:59:57.535589+00:00  ALLOW executed        http.get @ http://127.0.0.1:9000/api/v1/health
2026-10-28T22:01:08.252038+00:00  DENY                  http.delete @ http://127.0.0.1:9000/api/v1/clusters/prod-db
    reason: out of scope | no credential released | not executed  [receipt_5951b97714dd47e182daff0f9b462fe0]
2026-10-28T22:02:47.507696+00:00  DENY                  process.exec @ /usr/bin/id
    reason: out of scope | no credential released | not executed  [receipt_44234d14f27d4ff29780f1fc63e33a15]
```
All 31 receipts verified against the public key without errors.

---

### Evaluation Summary

| Capability Tested | Airlock Claim | Observed Behavior | Verdict |
| :--- | :--- | :--- | :--- |
| **Authority Discovery** | Statically scans AST for external callsites | Detected `http.get`, `http.post`, `http.delete`, `process.exec` | **Verified** |
| **Authority Gating** | Prevents unreviewed powers from executing | Refused execution until `airlock init --approve` was run | **Verified** |
| **CI Diff & Check** | Flags newly introduced powers in PRs | `airlock diff` and `airlock check` flagged new DELETE action | **Verified** |
| **Network Interception** | Blocks unapproved calls before transport | Mock server never received the unauthorized `DELETE` | **Verified** |
| **Consequence Reservation** | Prevents blind duplicate retries | Blocked identical repeat POST; effect held in `AMBIGUOUS` state | **Verified** |
| **Process Mediation** | Gates local binary execution | Permitted approved `whoami`, blocked unapproved `id` | **Verified** |
| **Audit Receipts** | Ed25519 hash-chained tamper-evident log | 31/31 receipts verified against public key | **Verified** |

### Developer Takeaway
Actenon Airlock functions as advertised. It addresses a major blindspot in AI agent engineering: **silent privilege expansion and duplicate consequential execution**. By combining static AST discovery with runtime policy enforcement and idempotency reservation, it provides deterministic boundaries for cooperative Python agents without modifying application business logic.