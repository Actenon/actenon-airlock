# HTTP effect ownership in the actual Airlock broker

Before this change, a lost response could be blindly repeated from a fresh run,
and a generic HTTP response was reported as an observed committed consequence.
The original two failing cases are preserved in before.xml. The separate real
cold-start failure discovered while adding the two-process product race is
preserved and repaired in Permit #28; no race test was removed or weakened.

Airlock now invokes the existing Permit effect reservation / budget transaction
and the independent public-key-only Kernel EffectProtector at the actual HTTP
callback. Scan's read_only classification selects the repeatable path; there
is no new Airlock risk classifier. Unresolved authority still uses Permit's
scope refusal and releases no credential. Proofs and receipts remain signed.

The default reviewed fingerprint includes method, canonical exact URL, body
hash and all caller headers, with typed stable parent credential references.
Source digest, fresh grant/proof/attempt IDs and random credential handles are
excluded from logical identity. Request body/header hashes remain in the exact
signed action. The Kernel recomputes the fingerprint and atomically claims
ownership before the callback materializes credentials. Namespace derives from
the trusted local project public key and the ledger persists between runs.
A changed credential principal or API-specific semantic retry needs reviewed
provider identity configuration; generic byte identity is not a universal
business-effect identifier. Distinct bodies and literal-vs-credential headers
cannot collapse into the same default effect.

Generic HTTP response completion does not prove COMMITTED. The normal client
receives its response, and the signed observation says response-received,
transport_completed=true, outcome=AMBIGUOUS, execution_occurred=null. Ownership
remains held. Lost responses produce OUTCOME_UNKNOWN / AMBIGUOUS. Settlement
failure after transport leaves DISPATCHING held and produces unknown evidence,
never a false pre-execution DENY or a budget refund. No timer releases ownership.
A confirmed pre-dispatch refusal can settle NOT_EXECUTED using the trusted
parent's non-execution observation. The operator reconcile CLI and authenticated
provider observers are not yet shipped.

Eight direct product cases cover restart after source/credential-handle changes,
raw-secret exclusion, generic response certainty, repeatable Scan read operations,
settlement failure, distinct request bodies, mismatched Content-Length, typed
credential identity and two spawned Airlock processes sharing one HTTP dispatch
and an intact signed journal. Existing requests, httpx sync/async, urllib and
provider-SDK client workflows remain unchanged and pass. The old repeated POST
revocation/budget tests now use distinct request bodies: they still require two
legitimate provider calls and valid mutable state, while the new tests directly
require one call for an identical held effect. The old false EXECUTION_FAILED
and observed-execution expectations are replaced by stronger unknown-evidence
assertions, rather than relaxing the consequence contract.

Full suite: 102 passed, zero skips. The immutable source stack is Scan ee971b4,
Protocol 3442bf3, Kernel 9dd6af8 (#47), Permit 11c9aad (#28). Doctor, Ruff and
format checks pass. CI independently installs these pins and the built wheel.
No real provider accounts, credentials or paid model calls are needed.

This is cooperative local Python HTTP protection, not an OS jail or cross-host
ownership. Process/filesystem releases remain unobserved. Compiled target-scoped
capability identifiers still require migration to the final Scan-named portable
resource model. Bounded dynamic authority, semantic GraphQL, PostgreSQL/MCP,
protected mode, exact operator approval/reconciliation, cumulative budgets,
independent SDK effect parity, external-agent acceptance, competitive benchmark,
registry packages and G1–G40 acceptance remain programme work. No package,
tag or release is published by this PR.
