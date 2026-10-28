# Actenon Airlock: Cyber-Insurance, SOC2 & ISO/IEC 42001 Underwriting Guide

Actenon closes **The Execution Gap** in enterprise AI deployment: transforming unconstrained, opaque agent tool execution into pre-merge static authority discovery (`actenon-scan`), bounded cryptographic capability grants (`actenon-permit`), stateless edge proof verification (`actenon-kernel`), and a tamper-evident, hash-chained audit ledger (`actenon-airlock`).

---

## 1. Why Underwriters & Auditors Require Actenon

Traditional application logs cannot prove what an autonomous agent was *allowed* to do, whether a human or parent policy bounded its spend, or whether raw API keys were exposed to prompt-injected agent memory.

Actenon provides four machine-verifiable guarantees out of the box:

1. **Pre-Merge Static Authority Discovery (`actenon-scan`):**
   Every consequential code change produces a deterministic `AIRLOCK AUTHORITY DIFF` (`+ database.delete production/customers`, `+ http.post api.stripe.com/v1/refunds`), separating `RESOLVED` static targets from `HEURISTIC` evidence and refusing to widen dynamic unknowns to `*`.
2. **Bounded Authority & Ancestor-Charged Delegation (`actenon-permit`):**
   Agents execute under HMAC-SHA256 `Grants` with hard spend caps, rate limits, expiries, and UCAN-style attenuated sub-agent delegation where every sub-agent spend is atomically charged against every ancestor grant in the delegation chain.
3. **Zero-Exposure Credential Brokerage & Independent Witness Reconciliation (`OpenAPIDynamicAdapter`):**
   Raw credentials (`STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, database credentials) are resolved server-side *only* after single-use Ed25519 `PCCB` proof verification. Cross-origin HTTP redirects and private-network SSRF targets are blocked before credentials are attached, and post-action `reconcile()` verifies real-world side effects via an independent read-only witness check (*"Unknown is not failed—never blindly retry an uncertain consequential action"*).
4. **Stateless Edge Verification & Hash-Chained Audit Ledger (`actenon-kernel` + `actenon-airlock`):**
   Every allowed execution (`ALLOW`) and every blocked adversarial attempt (`PARAMETER_MISMATCH`, `REPLAY_DETECTED`, `BUDGET_EXCEEDED`, `SCOPE_VIOLATION`, `AUTHORITY_REVOKED`) is signed with Ed25519 over `ACTENON-JCS-STRICT-1` canonical JSON and chained via SHA-256 (`prev`) in `.airlock/local/receipts.jsonl`.

---

## 2. Control Mapping (SOC2, ISO/IEC 42001, Cyber-Insurance)

| Framework | Control ID | Requirement | Actenon Cryptographic Evidence |
| :--- | :--- | :--- | :--- |
| **SOC2 Trust Services** | `CC6.1` | Logical access security & least-privilege enforcement | Signed `.airlock/approved.json` manifest + HMAC `Grant` scope binding (`SCOPE_VIOLATION` refusals on unscanned targets) |
| **SOC2 Trust Services** | `CC6.6` | Boundary protection & secret isolation | Server-side credential brokerage (`credential_released` boolean in receipts; zero raw secrets in agent process or ledger) |
| **SOC2 Trust Services** | `CC7.2` | Anomaly & tampering detection | Ed25519 `PCCB` `ACTENON-JCS-STRICT-1` parameter hash verification (`PARAMETER_MISMATCH` and `REPLAY_DETECTED` refusals) |
| **ISO/IEC 42001** | `A.6.2.6` | AI system lifecycle & pre-deployment validation | Pre-merge `actenon-scan` + `airlock check` CI gate blocking unreviewed authority expansion |
| **ISO/IEC 42001** | `A.8.4` | Human oversight & autonomous spend bounds | Tiered autonomy bands (`ALLOW`, `REQUIRE_APPROVAL`, `DENY`) + atomic ancestor spend caps (`BUDGET_EXCEEDED` refusals) |
| **ISO/IEC 42001** | `A.9.3` | Post-action observability & state reconciliation | Independent read-only witness `reconcile()` + signed observer attestations |
| **Cyber-Insurance** | Underwriting Verification | Actuarial proof of bounded blast radius & kill switch | Immediate session revocation (`AUTHORITY_REVOKED`) + offline verification via `verify_ledger()` and `export_compliance_bundle()` |

---

## 3. One-Command Ledger & Compliance Bundle Verification

Auditors and cyber-insurance underwriters can verify the entire hash-chained receipt and refusal ledger offline using the committed public key (`.airlock/public-key.json`):

```python
from actenon_airlock import export_compliance_bundle, verify_ledger

verification = verify_ledger(".")
assert verification["ok"] is True

bundle = export_compliance_bundle(".", output_path="compliance-bundle.json")
assert bundle["ledger"]["ok"] is True
```

Or run the self-contained 60-Second CISO Proof directly from the terminal:

```bash
python -m actenon_airlock.ciso_proof
```
