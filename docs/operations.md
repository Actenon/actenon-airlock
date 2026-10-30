# Recovering trusted Airlock execution state

Protected Mode keeps keys, approval, receipts, replay state and effect ownership outside the agent container. Preserve that boundary. This guide covers the candidate's fail-closed recovery checks; it does not grant permission to clear an ambiguous effect.

Stop all supervisors using a project before restoring or migrating its state. Preserve the current state as evidence, including SQLite WAL files. Use SQLite's backup mechanism or a consistent stopped snapshot; copying a live main database without its WAL can lose ownership. Do not replace a database with an empty store, delete receipts, rotate the project key or edit reservation rows to make startup succeed.

Keep the project public key and recent signed journal checkpoints independently of the execution host. Before recovery, verify an exported journal with the independently retained inputs:

```sh
airlock verify-evidence --journal /recovery/receipts.jsonl \
  --public-key /independent/public-key.json \
  --checkpoint /independent/checkpoint.json
```

An `ANCHORED` result establishes extension of that checkpoint, conditional on the trusted key and checkpoint selection. Later entries remain unanchored. Signature validity does not establish provider success. A checkpoint selected from the same rolled-back backup does not detect that rollback.

Restore ownership at least as recent as the independently established history. Startup rejects invalid receipt chains, missing journal-recorded attempts and terminal outcomes inconsistent with the store. Authorized receipts contain ownership references even if execution died before a completion receipt. An older NOT_EXECUTED attempt cannot replace a missing later owner. Missing completion evidence may therefore require trusted recovery even when the store settled successfully; the safe default is to hold execution.

Use authenticated provider observation and the existing reviewed operator reconciliation flow for ambiguous effects. Do not infer non-execution from a timeout, error status, absent acknowledgement or a valid local signature. Conflicting or replayed reconciliation evidence must not be accepted.

The independent-security candidate also refuses prior live header-dependent generic effects because its conservative header-independent identity cannot safely inherit those holds without an explicit migration. It inventories surviving database owners even if the journal is absent. No automatic migration is provided. Preserve the old deployment state and arrange a reviewed, authenticated migration before upgrading a deployment with these effects. A committed legacy effect cannot simply be marked NOT_EXECUTED.

If both the durable ownership database and receipt history have been destroyed or jointly rolled back, the runtime has no external authority from which to reconstruct them. An independent checkpoint may detect the problem offline; it cannot recreate the missing provider state or ownership records. Keep execution stopped until an authoritative recovery path exists.

See [the independent evaluation](../release/independent-security/REPORT.md) for executable controls, exact dependency pins and the limits of the recovery check. The additional read-only ownership inventory depends on the pinned Permit SQLite schema; review it when upgrading Permit.
