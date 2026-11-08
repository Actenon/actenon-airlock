# AIRLOCK NORTH STAR: EXACT-CANDIDATE ACCEPTANCE REPORT (2026-11-08)

**Verdict: NOT READY.**

- **No-cost checks:** C3 passes every one run here, plus its exact-head CI (run `42520916211`, green and independently verified).
- **Items 5, 6 and 7:** no evidence is bound to C3.
- **Items 8 and 9:** not started.
- **`main`:** the trusted release rules there do not contain the accepted bar.
- Nothing here is a formal release-gate decision or an owner record. The "PASS" for items
  1–4 is the admission script's evaluation under C3's own committed rules. The trusted
  checkout, `main`, cannot yet produce it.

## 1. Candidate identity

Full record: `candidate-identity.json`.

| | C1 (superseded) | C2 (superseded) | **C3 (evaluation candidate)** |
|---|---|---|---|
| Commit | `67b348c43a1d…` (PR #28 head) | `dc7ed54f93dd…` (draft PR #29) | **`5b1f0f29dba683c6a4f40d74ea404183224e3c7d`** (`fix/north-star-ns4`, draft PR #31, stacked on #29) |
| Installable product commit | `733bd48` | `eba7ef796b70…` | `eba7ef796b70…` |
| Source digest (`scripts/source_identity.py`) | `45d935f6…` | `da323e93…` | **`da323e93157e33ac05e18e177b0b24060eaac39c34e891f309565bf69e17ec55`** |
| Why superseded | No-cost verification found NS-1 to NS-3 | Independent verification of its green exact-head CI found NS-4 | |

No live evidence existed for C1 or C2, so superseding them cost only re-running the free checks.
C3 is C2 plus one CI-configuration commit; its source, containers, dependency pins, contract
data and acceptance harnesses are byte-identical to C2's.

| Identity element | C3 (same as C2) |
|---|---|
| Dependency commits | Scan `16388227…`, Protocol `a2e0e08f…`, Kernel `ead6a00a…`, Permit `85aa3ae2…` (all four are open-PR heads, and anonymously retrievable) |
| Images, frozen by ID | Compute `8ccf4af1…`, Claude Code `2c625f0f…` (the image used by the Gate 5 matched and Gate 6 runs), Codex `c449dec5…`, Aider `b575a8f4…`, gate7-python `8cb52579…`, gate7-go `13938348…`, gate7-node `14e4fe4b…` |
| Image reproducibility | Dockerfiles are identical to those of every historical run. Builds are **not** bit-reproducible: a rebuild produced new IDs, with the same pinned package versions |
| Agents | Claude Code 2.1.308 with `claude-opus-5-5` at 4 / 5 / 0.2 / 20 USD per MTok (checked against the Claude API reference). Codex CLI 0.166.0 (prices not independently checked). Aider 0.86.2 (local model) |
| Harnesses | Tree hashes of `acceptance/claude-code`, `acceptance/gate7`, `acceptance/github-consequence`, `acceptance/live-github` and the four scripts, in the identity file |
| Independent verifier | `verifier/airlock_verify.go`, source SHA-256 `ed109a1b3c8fbec0…`, built with go1.25.14 |
| Admission rules | `gates.json` at `main` `ba4ca936…` (no release bar), at C1 `c6ee6674…`, at C2 and C3 `7d54af2d…`. `RELEASE_BAR.md` matches its pin `51aae87d…` |
| Gate 5 freeze (no cost) | `northstar-live/gate5/matched-freeze-5b1f0f2.json`, SHA-256 `a17308d0e15aef45…`. It differs from the superseded C2 freeze only in `source_commit` |

## 2. Original acceptance matrix (A–F)

| Section | Status | Evidence | Gap |
|---|---|---|---|
| A: one candidate, compatibility map | VERIFIED IN THIS ENVIRONMENT (Python graph) | `candidate-identity.json`; registry-shape dry run | Go and Rust SDK pin reconciliation not re-examined here |
| B: exact authority and request identity | VERIFIED IN THIS ENVIRONMENT (Airlock suites) | 2,378 integration tests; duplicate-key handling reviewed on every model path | Cross-implementation canonical corpus not rerun |
| C: external boundary | VERIFIED IN THIS ENVIRONMENT (macOS Docker Desktop) and on Linux CI (C2, C3) | 198 container tests including bypass attempts and credential isolation; independent containment | Disk quota not enforced (documented) |
| D: effect ownership and recovery | VERIFIED IN THIS ENVIRONMENT (local host) | Effect durability, reconciliation and recovery suites | No multi-host claim |
| E: useful unchanged agent | **BLOCKED** | Historical live runs only, on other source | Experiments A–C on C3, after owner approval |
| F: install, review, independent evidence | PARTIAL | Clean wheel install; one entry point; reproduction harness; independent verifier (142 journals, 0 disagreements); tamper tests | Public-registry install (BLOCKED); two independent operators (NOT STARTED) |

## 3. Release bar

| # | Requirement | Status | Why |
|---|---|---|---|
| 1 | One candidate holding every supported agent | **VERIFIED under C3's rules** | The gate, under C3's committed rules, reports PASS from exact-head run `42520916211`. `verify_ci.py` independently re-scored the JUnit against the contract. Under `main`'s rules the gate cannot admit it (`main`'s contract allows 2 integration skips). This is the gate's evaluation, not an owner decision |
| 2 | Exact authority, enforced boundary, truthful effect ownership | **VERIFIED under C3's rules** | As item 1 |
| 3 | A stranger can see it work, with no key and no cost | **VERIFIED under C3's rules** | In run `42520916211`, the documented install and first run passed cold on Linux for Python 3.11 and 3.12, as part of `candidate_ci`. The same caveat about `main` applies |
| 4 | One entry point from task to reviewed patch | **VERIFIED under C3's rules** | As item 1 |
| 5 | Real model, matched baseline, attacks from the same environment | **BLOCKED** | No run on C3. Experiment A is prepared (`GATE5_AUTHORISATION_REQUEST.md`) and not authorised. The historical pair is bound to `f04f60f`, under a different grant context |
| 6 | One real GitHub write, confirmed by independent readback | **BLOCKED** | No run on C3. The historical write is bound to `9fd8b94` |
| 7 | Three repositories and ten agent cases | **BLOCKED** | The original programme has a genuine FAIL (case 2) and 3 cases never run, and it is bound to `6868406`. A pre-registered v2 is needed |
| 8 | Install from public registries alone | **BLOCKED** (the gate reports FAIL) | Pre-release version; Git dependencies; nothing published |
| 9 | Two independent operators on fresh machines | **NOT STARTED** | Operator pack prepared and run end to end on this machine; no operator recruited |
| 10 | The owner accepts this bar | **PARTIALLY VERIFIED** | Accepted on 2026-11-01, and the pin matches in the candidate. But `main`, the gate's trusted checkout, has no bar, so the real gate cannot see it |

## 4. Historical evidence

See `HISTORICAL_ADJUDICATION.md`. In short:

- 28 of 37 modules, including the entire enforcement core, are byte-identical to the code the
  Gate 5, 6 and 7 live runs tested.
- Their findings are good evidence about those components.
- None can become C3's record: each is bound to another commit. Gate 5's grant context changed,
  and Gate 7's programme contains a genuine FAIL.

## 5. No-cost engineering

See `NO_COST_RESULTS.md`.

**Four defects found, reproduced and fixed** (NS-1 to NS-4). Each has a minimal reproducer and a
regression test that fails on the candidate it was found in:

| ID | Found in | Defect |
|---|---|---|
| NS-1 | C1 | Airlock's verifier accepted a non-canonical, or duplicate-keyed, final receipt line |
| NS-2 | C1 | Two credential-isolation tests ran in no CI job |
| NS-3 | C1 | The trusted CI contract made items 1–4 FAIL on green CI |
| NS-4 | C2 | NS-3's fix was measured on a full-history clone. The shallow integration checkout skipped two pin tests the contract requires, so items 1–4 still FAILED on C2's fully green CI |

**Suites:**

| Suite | C2 (local, frozen images) | C3 (local) |
|---|---|---|
| Integration | 2,377 passed, 62 skipped (all allowed), 0 failed | 2,378 passed, 62 skipped (all allowed), 0 failed |
| Container job | 198 passed, 0 skipped | not rerun locally (byte-identical tests, images and product code); see CI |
| Independent containment | 1 passed | see CI |

**Exact-head CI:**

- C1: green in run `42188115271`.
- C2: green in run `42519985401`, but independently re-scored as failing its contract (NS-4).
- C3: green in [run 42520916211](https://github.com/Actenon/actenon-airlock/actions/runs/42520916211): all 6 jobs passed, and independently verified against C3's own contract.

**Independent CI verification** (`verify_ci.py`, GitHub API and standard library only) checks:

- the run's head and repository;
- every job's conclusion;
- each artifact's bytes against GitHub's digest;
- the JUnit reports against the candidate's own contract;
- the dependency commits CI installed.

Separately, the source digest was recomputed from GitHub's tarball of the commit and from the
wheel CI built.

**Admission gate (authenticated):** 

- **C3's rules:** `candidate_ci` and bar items 1–4 **PASS**. The dependency graph PASSES. Items 5–7 and 9 are BLOCKED (no owner records), 8 FAILS (pre-release) and 10 PASSES. Overall **NOT READY**.
- **`main`'s rules:** NOT READY, structurally. 29 G1–G40 gates are UNDEFINED, and `candidate_ci` FAILS on `main`'s 2-skip contract.
- **C2, for the record:** items 1–4 FAILED on its green run, which is NS-4.

## 6. Live programme

See `LIVE_PROGRAMME.md`. It is pre-registered and **not authorised**:

| Experiment | Item | Runs | Max estimated spend | GitHub writes |
|---|---|---|---|---|
| A | 5 | 2 | $4 | 0 |
| B | 6 | 1 | $2 | 1 |
| C (gate7-v2) | 7 | 17 | $51 | 2 |
| **Total** | | **20** | **$57** (expected about $3–5) | **3** |

- **Gating:** each experiment runs only after the previous one passes.
- **No retries.**
- **Stop conditions:** listed in full in the plan.
- **Credentials:** new and scoped. The previously exposed keys must be revoked first.
- **C's baseline mode:** not built yet.

## 7. Independent reproduction (item 9)

`reproduction/` holds the operator pack:

- `OPERATOR_GUIDE.md`, `RECRUITMENT.md` and `OPERATOR_RECORD.md`;
- `reproduce.sh`, the one command;
- `check_results.py`, standard library only;
- `expected.json`.

It was run end to end on this machine against C2, with freshly built images (see
`reproduction/LOCAL_DRY_RUN.md`). `expected.json` now names C3, whose source digest is the same.
The dry run has not been repeated for C3.

- **Matched:** identity, wheel build, dependency commits, doctor, the integration contract
  (2,377 passed), the independent verifier (142 journals), the tamper self-test (3 of 3) and the
  provider records.
- **Did not match:** two container tests hit `Docker operation failed: run` under heavy load.
  Immediate reruns passed 7 of 7. This is classified INTERMITTENT ENVIRONMENT, not a pass, and
  the operator guide now pre-registers how operators report it.

This machine's run is a technical rehearsal, **not** an operator result. **0 human operators.**

## 8. Registry readiness (item 8)

See `REGISTRY_READINESS.md`.

- All five distributions build.
- Only Airlock's metadata blocks PyPI: Git dependencies and a dev version.
- A release-shaped variant installs from PyPI plus local wheels, with 0 Git fetches.
- Owner decisions R1–R5 are listed.
- A metadata-only release commit should be frozen **before** the live programme, or the live runs
  must be repeated on it.

## 9. Security limitations (each guarantee holds only as demonstrated)

- **Containment** is shown for Docker on this macOS machine and on GitHub's Linux runners (C1),
  with the trusted host, Docker and kernel assumptions in `docs/security-model.md`. No claim
  holds against kernel or Docker escapes, or against an attacker controlling the user account or
  `.airlock/local`.
- **A valid signature is not provider truth.**
  - The independent verifier proves what Airlock recorded.
  - Provider state is confirmed only by readback.
  - For the private Gate 6 repository, outsiders can check only that the published records are
    consistent.
- **Journal completeness depends on a checkpoint.** 67 of the 142 committed journals are
  unanchored, so truncating them would be undetectable.
- **Effect ownership is coordinated on one host only.**
- **Spend is estimated** from reported usage at owner-approved prices. It is not a bill.
- **Docker images are not reproducible.** Their identity rests on recorded IDs.

## 10. Final verdict: NOT READY

The smallest path to CANDIDATE READY, in order:

1. **Done (no cost):** C3 is pushed as draft PR #31, and its exact-head CI is green and independently verified (run `42520916211`).
2. **Bring the trusted rules to `main`:** draft PR #32 (rules only, verified). **Owner merge
   decision; not authorised.**
3. **Decide the release identity** (`RELEASE_IDENTITY_DECISION.md`, D1–D9). Then publish the
   four dependencies (owner, irreversible) and create the release-shaped final evaluation SHA,
   C4b. **Live acceptance waits for C4b**, so that it runs only once (owner decision of
   2026-11-08).
4. **Run Experiments A, B and C** on C4b, each separately approved. The owner then reviews the
   evidence and writes records 5–7 onto `main`.

RELEASE READY additionally needs:

- **Item 8:** the four dependencies published, with their hashes matching C4b's `uv.lock`. The
  gate checks only the dependencies; Airlock itself is published afterwards, by `release.yml`.
- **Item 9:** two operators, bound to C4b.
