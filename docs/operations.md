# Operating Airlock

One supervisor on one host, with one project state directory. **Multi-host and
high-availability deployments are not supported.** Effect ownership lives in a local
SQLite database, so two hosts sharing a project could not exclude each other.

| Topic | What to do | Evidence |
|---|---|---|
| Install | [Golden path](golden-path.md) step 1. Dependencies are pinned to exact commits. | Fresh-environment install from built artifacts |
| Upgrade | Stop every supervisor, take a stopped snapshot, install, run `airlock doctor`. Startup refuses state it cannot prove safe; see [Recovering trusted execution state](#recovering-trusted-execution-state). | `tests/test_legacy_upgrade.py` |
| Limits | Each container has 1 GiB of memory, 2 CPUs and 128 processes, with a read-only root and no network. A run has 128 model calls, 4096 output tokens per call and 64 KiB request text. Set the model read timeout with `--model-read-timeout`. Results over these bounds are refused, not truncated. | `tests/test_protected.py`, `tests/test_model_timeouts.py` |
| Lifecycle | `setup`, `work`, `capture`, `verify-candidate`, `review-candidate`, `init --approve`, `publish`, `reconcile`. Each run gets a new workspace under `.airlock/local/runs`. | `tests/test_guided_workflow.py` |
| Supervisor failure | The agent loses its only route out, and inference fails. Nothing falls back to Local Mode. An in-flight dispatch stays `AMBIGUOUS` and owned across restart. | `tests/test_effect_durability.py` |
| Emergency stop | `airlock stop --reason "..."` kills the running agent within about a second and refuses dispatch and new runs. A dispatch already in flight is not recalled; it stays held. `reconcile` still works. `airlock resume --reason "..."` clears the stop and changes no effect. | `tests/test_guided_workflow.py` |
| Revoke approval | `airlock init --approve --clear-github` removes publication authority. Held effects stay held. | `tests/test_guided_workflow.py` |
| Rotate a provider credential | Replace it in the supervisor's environment and rerun. Effect identity does not depend on the credential, so rotation cannot release a held effect. | `tests/test_guided_workflow.py` |
| Rotate an observer key | Approve a new `--reconciler-key` and drop the old key from approval. Past settlements stay verifiable; the old key can submit nothing new. | `tests/test_reconciliation.py` |
| Back up | Stop first, or use SQLite's backup mechanism, and keep WAL files. Keep `public-key.json` and recent checkpoints off the host. | [Recovering trusted execution state](#recovering-trusted-execution-state) |
| Crash recovery | Restart. Startup cross-checks the journal against the ownership store and holds execution on any disagreement. | `tests/test_effect_durability.py`, `tests/test_independent_recovery.py` |
| Ambiguous settlement | Run `airlock reconcile effect_<id> --github-readback --operator-key <key>`. Readback never repeats the write. If it cannot confirm, the effect stays held; a timeout or 404 never proves non-execution. | `tests/test_guided_workflow.py`, `tests/test_github_observer.py` |
| Logging and redaction | Supervisor lines go to stderr. Receipts record digests and decisions, never a credential. Bound credentials found anywhere in project input refuse the run. Agent output is not redacted, because it is not trusted to contain only what you expect. | `tests/test_protected.py`, `tests/test_guided_workflow.py` |
| Diagnostics | `airlock doctor` for the boundary, `airlock status` for outcomes, `airlock receipts` for the journal, `airlock recovery-inventory` for stopped state. | `tests/test_independent_recovery.py` |

## Known limits

* The agent can read everything in its workspace copy, and it can send that text to
  the approved model through inference. Choose the model endpoint with that in mind.
* Docker shares the host kernel. This is container isolation, not a microVM.
* A rollback of both the journal and the ownership store is detectable only with a
  checkpoint held elsewhere, and it cannot be repaired from local state.
* The agent's own answer can be wrong. `TESTS_PASSED` covers the tests you supplied.

## Compatibility

| Component | Validated | Not validated |
|---|---|---|
| Host | Ubuntu amd64 in CI; macOS arm64 through Docker Desktop 29.x | Windows; native Linux arm64 |
| Python | 3.11 and 3.12 | Other versions |
| Agent | Aider 0.86.2 from its pinned image | Any other agent |
| Model route | Local Ollama through the OpenAI-compatible API | Hosted providers in an end-to-end agent run |
| Provider | Synthetic GitHub Contents API | Live GitHub, until an owner authorizes a disposable test |

# Recovering trusted execution state

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

## Upgrading header-dependent ownership (PR #17)

There is **no general automatic migration** from the earlier HTTP header-dependent
identity to the new byte-request hold. Old descriptors retain header digests, not
a provider consequence contract. They cannot prove that two requests with different
tenant, account, precondition, representation or idempotency headers describe the
same operation. Nor does changing a hash transfer the atomic ownership enforced by
Permit. Renaming rows, marking them non-executed, or starting an empty namespace
would manufacture permission to retry. PR #17 deliberately blocks startup when
any surviving legacy RESERVED, DISPATCHING, AMBIGUOUS or COMMITTED owner exists.

The new command is diagnostic and does not change the store, initialize keys,
create locks, migrate rows or authorize execution:

```sh
# First stop EVERY supervisor and prevent automatic restart.
# Use the preserved, stopped snapshot; direct stdout outside it.
airlock recovery-inventory --path /recovery/project --json \
  --public-key /independent/public-key.json \
  --checkpoint /independent/newest-checkpoint.json > /review/inventory.json
```

It copies regular database/WAL files into a disposable directory before using
SQLite, so even WAL indexing cannot modify the source. It hashes the captured
public key, journal and SQLite files, lists every reservation (including historical
NOT_EXECUTED attempts), flags live legacy identities, and compares journal attempts
and outcomes with database ownership and its latest event. It reads no private keys.
It refuses interrupted rollback-journal recovery, source changes observed during
capture, bad signatures, torn receipt appends and checkpoint disagreement. Preserve
all original files even when SQLite can recover a disposable copy. The snapshot
comparison is a diagnostic check, **not an atomic online backup protocol**.

Exit 2 means BLOCKED. Exit 0 means NO_DETECTED_BLOCKER, not SAFE_TO_MIGRATE or proof
of completeness. Without `--public-key`, the key is labelled project-local-untrusted.
A supplied key/checkpoint is useful only if the operator actually obtained and kept
it independently. The inventory cannot detect a jointly rolled-back database and
journal against an equally old checkpoint, or reconstruct destroyed history.

Supported paths, with every old supervisor stopped before upgrading:

1. A genuinely new deployment with no prior effects, established operationally
   rather than inferred from missing files. Missing state is reported BLOCKED by
   inventory; it is never automatically treated as a new deployment.
2. An intact deployment whose retained descriptors already use the unchanged
   identity (including supported exact GitHub operations), with no legacy live
   holds. Reverify the journal, independently held checkpoint and database together.
3. Legacy attempts that are already authentically NOT_EXECUTED and whose retained
   journal and database agree. Preserve those attempts and all receipts. A new
   attempt may obtain the new identity; later ambiguous/committed ownership still
   blocks retries. No legacy records are rewritten.
4. An eligible unresolved legacy attempt for which an authorized observer can
   independently establish **actual non-execution**, bound to the original
   reservation, grant, action, descriptor and review sequence. Use the existing
   operator reconciliation flow; retain its signed intent and completion evidence.
   Test observations are explicitly about owned fixtures. An absent response or
   generic provider 200 is not sufficient evidence to release a production effect.

COMMITTED legacy ownership cannot take path 4. Unresolved effects without reliable
provider observation must remain stopped. Running the old code, rotating keys,
creating a fresh project/session/grant or deploying the new code beside the old
supervisor is not an approved workaround. The remaining operational choices are
to preserve the stopped deployment, or design and review a provider-specific
ownership migration separately; this PR does not supply or claim that migration.

Recovery after interruption:

- Before a signed reconciliation intent is durable, the original owner remains.
- After settlement but before its completion receipt, the database/journal
  disagreement blocks startup. With an intact journal, retry the **identical,
  still-valid** signed assertion through the existing reconciliation command.
  Its settlement is idempotent and cannot release a new reservation. Do not change
  the outcome, re-sign stale evidence, or remove the pending intent. An expired
  assertion needs trusted recovery and renewed evidence; expiry is not permission.
- A partial journal append stays blocked. Preserve it; there is no automated
  truncation or repair. Restore a consistent, sufficiently recent backup on a
  separate stopped recovery copy and verify it against the newest independent
  checkpoint and retained evidence. If no such history can be established, stay
  stopped. Restoring only an old database does not clear a newer journal attempt.

## Journal cost and verification reuse

Every append still holds the process-shared exclusive lock, reads the entire
journal, refuses a torn tail, and fsyncs both the journal and its directory. A
running `State` may reuse verification only when the current journal starts with
the **exact bytes** of its previously verified in-memory prefix, under the same
public key. It verifies every suffix, including its own last signed row and other
processes' rows. Signing alone does not validate nested observer evidence. Prefix
changes cause full verification; file size, timestamps and inode are never trusted.
There is no persisted verification cache or new authority record.

Cold processes and `verify-evidence` still verify every signature. This removes
repeated signature work for long-lived writers, but retains O(journal bytes) read
and comparison cost and O(journal bytes) memory per active writer. Cold-start and
concurrent cold-writer latency remain linear. A valid rollback remains detectable
only against independently preserved history; caching adds no completeness claim.
Run `python scripts/benchmark_receipts.py --output /review/journal-benchmark.json`
in the installed candidate environment to measure real signing, verification,
fsync and four-process contention at 100, 1,000 and 10,000 initial receipts.

The exact `341ce3a` milestone also has a legacy denial format that can leave a
NOT_EXECUTED database attempt with only an authorized journal reference and no
bound completion outcome. That pair remains **blocked**, even though the fixture's
provider observed zero requests. The database label alone is insufficient to
silently repair the signed history. Path 3 above requires agreement in retained
bound evidence; it does not cover this format. The reproducible old-source check is:

```sh
python scripts/verify_legacy_upgrade.py \
  --legacy-checkout /review/clean-milestone-341ce3a \
  --output /review/actual-legacy-upgrade.json
```

The script checks the exact commit and clean tracked source before executing it
against temporary projects and an owned loopback server. It demonstrates blocked
legacy ambiguity, blocked unbound non-execution, and retained duplicate protection
for an unchanged identity. It does not run or migrate a deployed project.
