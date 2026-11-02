# Field Test 1: Production Incident Triage & Local Interception

## Objective
Evaluate Actenon Airlock's foundational scanning, manifest generation, operator approval workflow, and runtime mediation for an autonomous Python triage agent.

## Workflow
1. **Initialize Airlock:** `airlock init`
2. **Scan Agent Code:** `airlock scan main.py`
3. **Approve Powers:** `airlock approve` (approving `http.get` on `/health` and `process.exec` on `whoami`)
4. **Execute Under Airlock:** `airlock run -- python3 main.py`

## Observed Outcome
- Approved operations (`requests.get`, `whoami`) execute successfully and emit cryptographically signed audit receipts.
- Unapproved execution (`subprocess.run(["id"])`) is intercepted and rejected with exit code 3 (`DENY`), leaving no unmediated traces.
