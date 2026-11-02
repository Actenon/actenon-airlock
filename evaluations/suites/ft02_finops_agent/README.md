# Field Test 2: FinOps Dispute & Refund Automation

## Objective
Demonstrate how Actenon Airlock resolves the "Agentic Deployment & Liability Deadlock" in enterprise finance workflows.

## Key Scenarios Evaluated
1. **Prompt Injection & Credential Exfiltration:** Untrusted prompt instructions redirecting sensitive payloads to unapproved drop points.
2. **Unauthorized Destructive Mutation:** Agent attempting destructive deletion of customer records.
3. **Double-Spend & Consequence Idempotency:** Agent retrying a financial mutation without operator re-authorization.

## Evidence
- Complete signed receipts exported in `evaluations/evidence/finops_compliance_bundle.json`.
- Full audit report in `evaluations/reports/02_finops_cost_optimizer.md`.
