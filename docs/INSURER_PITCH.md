# Actenon Airlock: Audit Evidence & Draft Control Mapping Guide (SOC2, ISO/IEC 42001, Cyber-Insurance)

> **Important Scope & Compliance Notice:** This document describes technical evidence artifacts produced by `actenon-scan`, `actenon-permit`, `actenon-kernel`, and `actenon-airlock`, together with **draft, unvalidated engineering control mappings** to SOC2 Trust Services Criteria, ISO/IEC 42001, and cyber-insurance underwriting inquiries. These mappings have **not** been validated by an external auditor or insurance underwriter and do **not** constitute actuarial proof or regulatory certification.

---

## 1. Technical Evidence Produced by the Actenon Stack

1. **Pre-Merge Static Authority Discovery (`actenon-scan`):**
   Static AST and call-graph reachability analysis produces an `AIRLOCK AUTHORITY DIFF` (`+ database.delete production/customers`, `+ http.post api.stripe.com/v1/refunds`), separating `RESOLVED` static targets from `HEURISTIC` evidence and refusing to widen dynamic unknowns to `*`.
2. **Bounded Authority & Ancestor-Charged Delegation (`actenon-permit`):**
   Agents execute under signed `Grants` with spend caps, rate limits, expiries, and attenuated sub-agent delegation where delegated spend is atomically reserved and charged against every ancestor grant in the delegation chain.
3. **Server-Side Credential Resolution & Experimental HTTP Witness Reconciliation (`actenon-permit`):**
   Credentials are resolved by the broker after single-use Ed25519 `PCCB` proof verification. In the experimental `OpenAPIDynamicAdapter`, credentials are pinned to a verified origin (`https://` required for non-loopback live calls), DNS resolution is bound to the outbound socket connection, and post-action `reconcile()` performs a read-only `GET` witness check, preserving `OUTCOME_UNKNOWN` on conflict or timeout rather than automatically retrying or releasing reservations.
4. **Edge Proof Verification & Hash-Chained Receipt Journal (`actenon-kernel` + `actenon-airlock`):**
   - **Edge PCCB Proofs (`actenon-protocol` / `actenon-kernel`):** Bound to `ACTENON-JCS-STRICT-1` canonical JSON digests (`actenon_protocol.canonical`) and verified with Ed25519 (`PCCBVerifier`) and atomic replay claims (`ReplayStore`).
   - **Airlock Receipt Journal (`actenon-airlock`):** Stored in `.airlock/local/receipts.jsonl` using Airlock's internal canonical JSON serializer (`actenon_airlock.common.canonical`), signed with `EdDSA` over `RECEIPT_DOMAIN` (`actenon-airlock/receipt/v1`), and linked via SHA-256 `prev` digests.
   - **Prefix Integrity vs. Completeness:** Offline verification via `verify_ledger()` proves the **prefix integrity and signature validity** of the rows present in `receipts.jsonl`. Detecting tail truncation or deletion of the entire journal requires comparing `chain_head_sha256` against an externally anchored checkpoint (`export_compliance_bundle(..., expected_head_sha256=...)`).

---

## 2. Draft Control Mapping (Unvalidated Engineering Reference)

| Framework | Control ID | Control Theme | Actenon Technical Artifact (Draft Mapping) |
| :--- | :--- | :--- | :--- |
| **SOC2 Trust Services** | `CC6.1` | Logical access security & least-privilege enforcement | Signed `.airlock/approved.json` (`actenon-airlock/authority/v1`) verified by `state.checked_in_approval()` + `Grant` scope binding (`OUT_OF_SCOPE` / `SCOPE_VIOLATION` refusals) |
| **SOC2 Trust Services** | `CC6.6` | Boundary protection & credential handling | Broker-side credential resolution (`credential_released` boolean in receipts; credential values redacted from adapter responses and absent from serialized receipts) |
| **SOC2 Trust Services** | `CC7.2` | Tampering & replay detection | Ed25519 `PCCB` verification over `ACTENON-JCS-STRICT-1` action hashes (`ACTION_MISMATCH` / `PARAMETER_MISMATCH` and `REPLAY_DETECTED` refusals) |
| **ISO/IEC 42001** | `A.6.2.6` | AI system pre-deployment validation | Pre-merge `actenon-scan` + `airlock check` authority diff gate |
| **ISO/IEC 42001** | `A.8.4` | Human oversight & spend bounds | Tiered autonomy (`ALLOW`, `REQUIRE_APPROVAL` with fail-closed default when unconfigured, `DENY`) + atomic ancestor spend reservations (`BUDGET_EXCEEDED`) |
| **ISO/IEC 42001** | `A.9.3` | Post-action observability & reconciliation | Signed observer reconciliation records (`actenon-airlock/reconciliation-observation/v1`) and `OUTCOME_UNKNOWN` preservation |
| **Cyber-Insurance (Draft)** | Technical Questionnaire | Blast-radius bounds & revocation | Mid-session grant revocation (`AUTHORITY_REVOKED`) + offline bundle verification via `export_compliance_bundle()` |

---

## 3. Verifying the Receipt Journal & Compliance Bundle

Verify the hash-chained receipt journal and checked-in authority approval offline against `.airlock/public-key.json`:

```python
from actenon_airlock import export_compliance_bundle, verify_ledger

verification = verify_ledger(".")
assert verification["ok"] is True

bundle = export_compliance_bundle(
    ".",
    output_path="compliance-bundle.json",
    expected_head_sha256=verification["chain_head_sha256"],
)
assert bundle["ok"] is True
assert bundle["approval_verified"] is True
```

Run the deterministic local fixture demonstration from the terminal:

```bash
python -m actenon_airlock.ciso_proof
```
