# PR #17 integration validation — 2026-10-30

**Verdict: suitable for reviewed integration into the inspected milestone, with explicit upgrade blocking retained. Not approval for unrestricted upgrades or product release.** No general migration of live header-dependent ownership is supplied. Deployments with unresolved legacy state must remain stopped unless a supported evidence-preserving path in [operations.md](../../../docs/operations.md) applies.

Implementation: `8e0208f7486d07739317ebfe1a558cfd0d313b64` on `codex/airlock-independent-security`.
Previous PR head: `d404d34a80e0d3a1e911e2b9e166d97d0f278933`.
Inspected target `feat/airlock-milestone-1`: `341ce3a2f10d2eafa5b07e74539a36e16d3dfac2`, unchanged on fresh fetch during this work.
Historical integrated baseline: `426bdaae9d4f854db877271177c4455b7e286631`.

The target is an ancestor; `git merge-tree --write-tree` produced tree `d9f3e4e5f0d2ce0b80f391558b946b15effef2fd` without conflicts. No Claude worktree, branch, signing state or database was edited. The final PR evidence commit only adds this report and results. GitHub checks must be assessed on that final head; earlier green checks are not substituted for the updated head. The final CI result is attached to PR #17 and the exported integration verdict after push.

## Legacy ownership: what is now supported

`airlock recovery-inventory` inventories an offline state snapshot without initializing Airlock, reading private keys, creating locks, opening the source SQLite database or changing any source file contents. SQLite opens only a disposable main/WAL copy. Source hashes, exact reservation references, state, legacy identity classification and latest event state are retained in the JSON result. Journal signatures, attempt consistency and an optional independently retained checkpoint are checked separately. Changed source files and interrupted rollback journals are blocking. The operator must stop all supervisors first; the double read is not a live transactional snapshot protocol.

The command is diagnostic, never execution authority. `NO_DETECTED_BLOCKER` does not prove historical completeness or provider truth. Local public-key substitution is not solved by reading the same key twice: the result labels a local key as untrusted; the operator must supply independently obtained inputs for an independent claim. No automatic migration, alias insertion, owner rewriting, namespace/key rotation or effect deletion is implemented.

A general migration is not defensible for these generic HTTP records. A retained digest and request bytes cannot establish provider semantics for tenant, account, precondition, representation and idempotency headers. Conversely, starting the new hash scheme without preserving the old hold loses SQLite's uniqueness protection. An executable negative control deliberately disables the startup guard and observes a second POST at the owned provider. With the guard enabled, fresh processes, changed headers and renewed source approval cannot dispatch it.

| Retained evidence | Upgrade result |
| --- | --- |
| Legacy RESERVED, DISPATCHING, AMBIGUOUS or COMMITTED owner | Startup blocked; owner and evidence retained |
| Legacy NOT_EXECUTED with matching bound journal completion | Retained without rewriting; one new authorized attempt may use current identity |
| Authenticated non-execution observation for an eligible unresolved attempt, journal intact | Existing reconciliation protocol may settle the exact attempt; positive control then dispatches once |
| Settlement durable, completion append failed without tearing journal | Startup blocked until identical still-valid assertion completes the protocol; no extra settlement or provider dispatch |
| Torn receipt, contradictory journal/DB, missing later reservation, restored old DB, corrupt DB | Blocked; no automatic repair/truncation/reset |
| Unchanged effect identity with retained ownership | Supervisor starts and refuses duplicate dispatch |
| Both DB and journal lost/rolled back without a newer independent anchor | History cannot be reconstructed or its loss reliably detected; remains a release/deployment assumption |

### Actual old-source control

The new harness runs the exact clean `341ce3a` source in a separate detached worktree, rather than inferring its behavior from new-code fixtures. Its outputs are preserved in [actual-legacy-upgrade.json](evidence/actual-legacy-upgrade.json).

- Header-dependent ambiguous effect: provider calls **1 → 1**, startup blocked after upgrade.
- Genuine legacy Kernel non-execution: provider calls **0 → 0**, upgrade blocked because the old denial format lacks a bound completion outcome. The trusted database label alone is not used to repair the signed journal. This older format is explicitly excluded from the supported matching-NOT_EXECUTED path.
- Unchanged identity: provider calls **1 → 1**, upgraded supervisor starts and refuses a duplicate despite changed tracing/content headers.

New permanent regressions additionally cover live ownership across SIGKILL after observed provider arrival, fresh spawned supervisors, COMMITTED observer settlement, new source approval, interrupted reconciliation intent/completion, partial writes, restored/missing databases, database event disagreement, WAL capture with an uncommitted transaction, descriptor substitution, symlink refusal and missing-state refusal. Read-only assertions compare all source file contents before and after inventory, including failure cases. Tests requiring non-execution observe zero calls at the owned endpoint; they do not relabel a dispatched POST as absent.

## Journal scalability without weaker integrity

At the original PR head, every append verified every prior signature. The change retains the exclusive process-shared lock, full file read, torn-tail refusal, signature and observer verification, fsync of the file and directory, and full offline verification. A running State instance reuses only an exact already-verified byte prefix under the same key. Any changed prefix triggers full verification; foreign suffixes and the writer's own last signed receipt are verified. Signing alone does not validate an embedded observer assertion. No file metadata or persisted verification index is trusted.

The cache is installed only after successful durability operations. New regressions cover same-size edits with restored mtime, replaced files, corrupted suffixes, partial appends, both fsync failure points, interleaved writers, invalid observer evidence inside a valid outer signature, changed verification keys and valid rollback. Rollback still has valid prefix integrity; the independently retained checkpoint detects divergence. The optimization makes no new completeness claim.

Measured on the same macOS ARM64 host, Python 3.12.13, using signed synthetic receipts, real fsync and four spawned processes. Each size has six serial appends (one cold, five warm) and sixteen concurrent appends (four per fresh process). Fixture construction is excluded. All final chains passed full verification. Small samples describe this run, not a capacity SLA.

| Initial receipts | Full verify before / after | Warm median before / after | Four-process batch before / after |
| ---: | ---: | ---: | ---: |
| 100 | 4.16 / 4.09 ms | 4.31 / 0.17 ms | 95 / 39 ms |
| 1,000 | 40.87 / 40.29 ms | 41.01 / 0.22 ms | 728 / 195 ms |
| 10,000 | 409.59 / 402.30 ms | 408.96 / 0.68 ms | 6,574 / 1,694 ms |

Exact measurements are authoritative in [journal-before.json](evidence/journal-before.json) and [journal-after.json](evidence/journal-after.json); the table rounds them. The 10,000-row cold append remained about 405 ms. The concurrent p95 remained about 1.68 seconds because cold writers still perform full verification under the lock. Every append still reads/compares O(journal bytes), and each State can retain O(journal bytes). This is not unbounded scalability or a change to checkpoint semantics. Source hashes bind both benchmark implementations to their corresponding commits.

## Final local integration evidence

**622 passed, zero skips, 114.51 seconds**, using the actual pinned candidate dependency graph and genuine Docker boundary. [JUnit](evidence/full-results.xml), [test output](evidence/full-tests.log), [source manifest](evidence/source-manifest.json), [checksums](evidence/SHA256SUMS.json).

Ruff check and format check passed across 60 source/test/script files. Sdist and wheel build passed. The rebuilt wheel was installed in the isolated wheel environment and imported outside the checkout; doctor passed against the pinned graph and actual Docker engine.

Dependencies remain:

| Component | Exact commit |
| --- | --- |
| Protocol | `a2e0e08fcd24b71eb1668204ba6bed00e4c63551` |
| Kernel | `7a1ad40581ce0f984f5b1cc4292f26d350cab311` |
| Permit | `b795a37cfa927c630605172f8ecaf073bfb2aa70` |
| Scan | `16388227a55a3b5a3ec392d1c70f3940b0c291c1` |

Docker server 29.9.2; image `actenon-airlock-codex-assurance:20261030`, ID `sha256:76b1e8f2b1d7917aa440ce98512d48f9f4b73cd50d06b5cd489191c6b31e50c0`. Isolated evidence directories and owned internal network resources were used.

The network-enabled controls delivered IPv4, IPv6, DNS, native libc, raw UDP, proxy and nested-process requests. The corresponding protected probes added **zero** requests to the sink. IPC replacement, symlink write, forged approval/reconciliation and unsupported HTTP were refused; approved inference through the trusted supervisor reached the owned HTTP fixture once. The existing GitHub workflow fixture still created its reviewed object once and held the ambiguous result against a duplicate with a new trace. These are harness-selected probes and fixture-provider observations, not model-selected attacks or actual hosted-model acceptance. See [transport observations](evidence/boundary-evidence/transport-observations.json) and [GitHub fixture outcomes](evidence/protected-evidence/github-container/outcomes.json).

Existing durability regressions, including eight-process single-dispatch ownership, process death after real provider arrival, header changes, invalid journals, missing databases and joint-history-loss limitation controls, passed again. Earlier authority/canonicalization tests also ran in the full Airlock suite. Cross-language dependency evaluation from the earlier PR remains historical evidence and was not relabelled as a new run.

## Integration and remaining blockers

Integrate through normal PR review into the inspected milestone. There is no source conflict to resolve and no dependency change. Deployment review must account for the intentional behavior changes already in PR #17: unknown HTTP header semantics fail closed, content-header changes cannot free an owned byte request, and live legacy header-dependent state blocks startup. This continuation adds diagnostic inventory and bounded verification reuse; it broadens no provider contract.

Release/deployment blockers remain: live legacy holds without a safe supported recovery path; old unbound NOT_EXECUTED history; unavailable/corrupt/insufficiently recent recovery evidence; total trusted local history loss without another authoritative persistent record; and the original unresolved North Star acceptance/release gates. Valid signatures do not prove provider success. Offline checkpoint satisfaction does not turn the checkpoint into a runtime external ownership service.

Historical frozen failures, earlier negative controls, milestone evidence, acceptance definitions and release-admission workflow are unchanged. New tests are engineering evidence, not replacement acceptance gates. No PR was merged, package published, tag created, service deployed, production credential used or paid model call made.

## Reproduction

Use the pinned environment specified in `pyproject.toml`; commands run in an isolated checkout:

```sh
python scripts/verify_legacy_upgrade.py --legacy-checkout /review/clean-milestone-341ce3a --output /review/legacy.json
python scripts/benchmark_receipts.py --output /review/journal.json
AIRLOCK_TEST_PROTECTED_IMAGE=actenon-airlock-codex-assurance:20261030 \
AIRLOCK_INDEPENDENT_EVIDENCE=/review/independent-boundary \
AIRLOCK_PROTECTED_EVIDENCE=/review/protected-boundary \
python -m pytest -q --junitxml=/review/results.xml
ruff check src tests scripts
ruff format --check src tests scripts
python -m build
```

Build the dedicated image with `docker build -f containers/Dockerfile.compute -t actenon-airlock-codex-assurance:20261030 .` if absent. Do not point any recovery or test command at a live deployment's `.airlock` state. The prior [independent evaluation](../REPORT.md) remains the source for the original PR's threat-model citations, frozen negative controls and detailed boundary qualifications.
