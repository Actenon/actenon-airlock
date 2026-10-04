# Resolve an uncertain effect

An HTTP timeout or response can leave the real consequence uncertain. Airlock
holds that effect and refuses an identical retry. Reconciliation records a
trusted observer's final answer; it never redispatches the original request.

First inspect the effect printed on its receipt:

```sh
airlock reconcile effect_<id>
airlock reconcile effect_<id> --json
```

Inspection changes no state. The snapshot includes the original attempt, grant,
subject, action, target, exact-action hash, effect descriptor hash, signed approval
digest and the ledger event reviewed. The action name comes from the original
signed Scan-derived authorization receipt.

## Approve a separate observer

On a trusted operator runner, create or load a private key outside the agent project:

```sh
airlock init --reconciler-key ~/.config/airlock/operator.key
airlock init --approve --reconciler-key ~/.config/airlock/operator.key
```

Review the displayed powers and observer fingerprint before approving. The first
command only proposes the observer. The second includes its public key in the
signed authority manifest. Ordinary reapproval preserves those keys. Removing a
key from a newly signed approval revokes its permission to submit new observations.

The file must end in `.key`, be owned by the operator with mode 600, be a regular
file with no hard links, and sit outside the project without a leaf symlink.
It is separate from the runtime receipt/proof signing key. Neither a submitted
public key nor an agent-selected observer name can authorize reconciliation.

Local file custody is a development option. Keep the private key unavailable to
the execution account. The cooperative Python worker refuses private-key reads,
link creation, and moves of external/private sources into approved destinations.
**Local Mode is not an OS jail.** Same-user hostile code, native execution and
approved uncontained subprocesses can bypass cooperative checks. Use an isolated
operator/provider signer; complete Protected Mode is still pending. This feature
does not claim to solve key custody for arbitrary hostile same-user agents.

## Establish the provider's final state

For a confirmed committed effect:

```sh
airlock reconcile effect_<id> --committed \
  --operator-key ~/.config/airlock/operator.key --evidence provider-result.json
```

Only when the observer establishes that the effect did not occur **and cannot
later commit from an outstanding request**:

```sh
airlock reconcile effect_<id> --not-executed \
  --operator-key ~/.config/airlock/operator.key --evidence provider-result.json
```

An absent object in an eventually consistent query, an HTTP error, a timeout, or
an arbitrary sleep does not establish final non-execution. Keep such effects
AMBIGUOUS. The evidence file is hashed; its contents and pathname are not recorded.
The signature authenticates the observer's assertion, not the underlying truth
of that assertion. Provider-specific checks must establish finality independently.

COMMITTED retains ownership and blocks retries. NOT_EXECUTED releases the held
reservation and budget through Permit, permitting a fresh attempt. The old proof
and attempt remain spent. A later retry has a different reservation; replaying
an old signed observation cannot clear it or refund budget again.

## Detached review

Add `--output` to write a signed observation without applying it:

```sh
airlock reconcile effect_<id> --not-executed \
  --operator-key ~/.config/airlock/operator.key --evidence provider-result.json \
  --output observation.json
airlock reconcile effect_<id> --approval observation.json
```

The application runner needs the public observer approval, not the observer's
private key or runtime credential environment. CLI observations expire after
five minutes; the signing helper permits a maximum ten-minute lifetime. Obtain
a fresh observation if the approved manifest or reviewed ledger event changes.
Permit checks event sequence and expiry after acquiring the settlement write
lock, atomically with ownership and budget changes. A decision reviewed before
dispatch cannot release a newer in-flight state.

Identical already-applied observations are idempotent. Conflicting observations
are refused. Independent processes racing conflicting answers yield one settled
answer; neither can overwrite it.

## Authenticated provider hook

Trusted parent integrations may use:

```python
from actenon_airlock.reconciliation import reconcile_from_provider

result = reconcile_from_provider(state, effect_id, trusted_provider_observer)
```

The observer receives the exact review snapshot and returns an envelope signed
by a separately approved observer key. `sign_reconciliation(request, private_key,
outcome=..., evidence_hash=...)` produces the envelope. The application independently
verifies the signature, project/approval binding, attempt, action, descriptor,
event and lifetime before invoking Permit's real settlement operation. Unsigned
claims are refused. Caller-owned mutable objects are frozen before verification.

Configure hooks in trusted parent code; never load a provider hook chosen by
agent input. No automatic provider-specific finality adapter is shipped here.
This interface does not authorize the agent to select a result.

## Verify evidence

```sh
airlock receipts
airlock receipts --json
```

A signed reconciliation intent is durable before settlement. Completion contains
the observer envelope, original signed authority approval, actual settlement time,
outcome and the linked intent receipt. Verification checks both signatures and
their bindings using the independently trusted project public key. Historical
observer signatures verify at their original settlement time, including after
expiry or later key rotation, without the private key or ledger.

An applied answer is labeled an **authorized observer attestation**. It does not
mean the CLI performed or independently observed a remote mutation. Receipts say
`provider_dispatched: false` and `credential_released: false`. A COMMITTED answer
reports the observer's assertion that the original consequence occurred.

If the intent append fails, settlement does not run. If the completion append
fails after settlement, the result explicitly says it was applied and retains
the signed intent and ledger; it does not claim the effect remains ambiguous.
Preserve both for recovery. This journal and SQLite settlement are separate
durable writes, not one cross-store transaction. No PostgreSQL cross-host or
externally anchored journal guarantee is claimed by this local workflow.
