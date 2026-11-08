# Historical Gate 5–7 evidence: what still applies to C2 (2026-11-08)

> **Candidate update, 2026-11-08:** the evaluation candidate is now **C3** (`5b1f0f2`). C3 is C2
> plus one CI-configuration commit (NS-4). Its `src/`, containers, dependency pins and acceptance
> harnesses are byte-identical to C2's, so everything below that is said of C2's code applies to
> C3 unchanged. Records must bind to C3.

Nothing here changes, rebinds or rescores any historical result. Every file under
`release/gate5-anthropic-live/`, `release/gate5-rerun-gate6/` and `release/gate7/` is unchanged.

## The one fact that decides formal status

| Evidence | Evaluated commit | Source digest | Bound to |
|---|---|---|---|
| Gate 5 matched (baseline and protected) | `f04f60f` | `60684fcd…` | that commit |
| Gate 6 real GitHub write | `9fd8b94` | `60684fcd…` | that commit |
| Gate 7 Batch A (cases 1–7, protected) | `6868406` | `60684fcd…` | that commit |
| **C2 (candidate)** | `dc7ed54` | **`da323e93…`** | — |

Owner records for items 5–7 must name the exact evaluated commit (`RELEASE_BAR.md`). **No
historical result can become a PASS for C2.** They are informative only.

## How far the code they tested is the code in C2

Measured with `scripts/source_identity.py`:

- **28 of 37 modules are byte-identical.** These are the whole enforcement core:
  - `protected.py`, `broker.py`, `adapters.py`, `wire.py`, `manifest.py`;
  - `agent_inference.py` (the Claude Code contract) and `responses_inference.py` (Codex);
  - `github_consequence.py`, `github_runtime.py`, `github_observer.py`;
  - `reconciliation.py`, `recovery.py`, `evidence.py`, `credential_preflight.py`;
  - `contained_agent.py`, `contained_bridge.py`, `worker.py`, `agents.py`, `model_constraints.py`.
- **Changed:**
  - `cli.py`: approval for agent projects now signs only reviewed grants. This **narrows** what
    is signed.
  - `protect.py`: the entry point, preflight and the toolchain probe.
  - `workflow.py`: verification profiles, tmpfs exec, the outcome vocabulary.
  - `state.py`: NS-1, stricter receipt verification.
  - `demo.py`.
- **Added:** `authority_review.py`, `demo_consequence.py`, `preflight.py`, `progress.py`,
  `style.py`.
- **Container definitions (`containers/`) are byte-identical,** and the Claude Code image the
  Gate 5 matched and Gate 6 runs used, `2c625f0f…`, is frozen for C2.

## Gate 5: matched useful work and containment

**Still applies, as evidence about unchanged code:**

- The real Claude Code 2.1.308 binary, the inference contract, the IPC bridge and the network-none
  container are the same bytes as in C2.
- The historical finding stands as a finding about those components: 4 canary deliveries in the
  baseline (2 hook runs × 2 routes), 0 under Protected Mode, and useful work in both.
- Its journals verify with **both** Airlock's verifier and the new independent Go verifier
  (see `NO_COST_RESULTS.md`).

**Needs fresh evidence:**

- The approval the protected run executes under changed. C2 signs only the model route for an
  agent project, where `f04f60f` signed every discovered power. Goal E requires the attacks
  "from that same protected environment and grant context", so the grant context must be C2's.
- The item-5 owner record must name the evaluated commit.

So item 5 needs a fresh matched pair on C2 (`LIVE_PROGRAMME.md`, Experiment A).

## Gate 6: one real consequential GitHub write

**Still applies:**

- `github_consequence.py`, `github_runtime.py`, `github_observer.py`, `reconciliation.py` and
  the broker are byte-identical. The historical run's controls (refusal before approval,
  altered variant, other repository and path, replay, an ambiguous reply settled by readback)
  exercised the same code paths C2 has.
- The published records agree with each other: the reviewed content SHA-256 `63543214…`,
  Airlock's readback (COMMITTED at `bafc2c43…`) and the owner's separate-token readback.
  `reproduction/check_results.py provider` checks this offline.
- Limit: the repository is private, so no outsider can read GitHub's state directly.

**Needs fresh evidence:** the record must bind to C2, and the Gate 6 repository must not be
reused. Experiment B makes **one** new write. It is required only because the record cannot be
rebound, not to generate more evidence.

## Gate 7: three repositories, ten cases

**The original programme (`acceptance/gate7/`, freeze `e7dac319…`) stays as recorded:**

- Batch A: 6 PASS, **1 FAIL** (case 2, click: the wrong warning text, and a pre-existing test
  file edited), 0 INCONCLUSIVE.
- Case 2 stays FAIL and is not rescored.
- Batches B (baselines), C (case 8) and D (cases 9 and 10) never ran. Batch B was NOT READY
  because of the observer's host-gateway blind spot.

**Under the original programme, item 7 cannot pass.** Goal E requires that "All scored tasks
must pass their preregistered checks", and case 2 failed. The programme is also bound to
`6868406`.

**What still applies:**

- The 6 PASS runs show that the unchanged Claude Code binary completed real upstream changes in
  Go, Python and TypeScript under the same enforcement core.
- Their seven journals verify with both verifiers.

**What is needed:** a new, separately versioned, pre-registered programme (gate7-v2,
`LIVE_PROGRAMME.md` Experiment C) on C2. It uses the same frozen cases and byte-identical
per-case criteria, all ten protected runs and seven baselines. Its baseline policy is new and
fixed before any run. It does not retry case 2 under the old programme. It is a new evaluation of
a new candidate, and it can fail the same way.

## Summary

| Item | Historical result | Reusable for C2's record? | What C2 needs |
|---|---|---|---|
| 5 | Useful work in both modes; 4 versus 0 canaries | No (another commit; the grant context changed) | Experiment A: 2 runs |
| 6 | One write, confirmed by two readbacks | No (another commit) | Experiment B: 1 run and 1 write |
| 7 | 6 PASS, 1 FAIL, 3 cases never run | No (another commit, and it contains a FAIL) | Experiment C: 17 runs and 2 writes, programme v2 |
