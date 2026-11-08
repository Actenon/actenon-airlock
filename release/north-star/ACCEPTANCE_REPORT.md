# AIRLOCK NORTH STAR: EXACT-CANDIDATE ACCEPTANCE REPORT (2026-11-08)

**Verdict: NOT READY.** C2 passes every no-cost check run on this machine. Items 5, 6 and 7 have
no evidence bound to it. Items 8 and 9 are not started. The trusted release rules on `main` do not
contain the accepted bar. Nothing here is a gate PASS or an owner record.

## 1. Candidate identity

Full record: `candidate-identity.json`.

| | C1 (superseded baseline) | **C2 (evaluation candidate)** |
|---|---|---|
| Commit | `67b348c43a1d…` (PR #28 head) | **`dc7ed54f93dd8d961029bb1dc50f499ed13e9dce`** (`fix/north-star-blockers`, local, **not pushed**) |
| Installable product commit | `733bd48` | `eba7ef796b70…` |
| Source digest (`scripts/source_identity.py`) | `45d935f6…` | **`da323e93157e33ac05e18e177b0b24060eaac39c34e891f309565bf69e17ec55`** |
| Why C2 | | No-cost verification found NS-1 to NS-3 in C1. No live evidence existed for C1, so superseding it costs only re-running the free checks |

| Identity element | C2 |
|---|---|
| Dependency commits | Scan `16388227…`, Protocol `a2e0e08f…`, Kernel `ead6a00a…`, Permit `85aa3ae2…` (all four are open-PR heads, and anonymously retrievable) |
| Images, frozen by ID | Compute `8ccf4af1…`, Claude Code `2c625f0f…` (the image used by the Gate 5 matched and Gate 6 runs), Codex `c449dec5…`, Aider `b575a8f4…`, gate7-python `8cb52579…`, gate7-go `13938348…`, gate7-node `14e4fe4b…` |
| Image reproducibility | Dockerfiles are identical to those of every historical run. Builds are **not** bit-reproducible: a rebuild produced new IDs, with the same pinned package versions |
| Agents | Claude Code 2.1.308 with `claude-opus-5-5` at 4 / 5 / 0.2 / 20 USD per MTok (checked against the Claude API reference). Codex CLI 0.166.0 (prices not independently checked). Aider 0.86.2 (local model) |
| Harnesses | Tree hashes of `acceptance/claude-code`, `acceptance/gate7`, `acceptance/github-consequence`, `acceptance/live-github` and the four scripts, in the identity file |
| Independent verifier | `verifier/airlock_verify.go`, source SHA-256 `ed109a1b3c8fbec0…`, built with go1.25.14 |
| Admission rules | `gates.json` at `main` `ba4ca936…` (no release bar), at C1 `c6ee6674…`, at C2 `7d54af2d…`. `RELEASE_BAR.md` matches its pin `51aae87d…` |

## 2. Original acceptance matrix (A–F)

| Section | Status | Evidence | Gap |
|---|---|---|---|
| A: one candidate, compatibility map | VERIFIED IN THIS ENVIRONMENT (Python graph) | `candidate-identity.json`; registry-shape dry run | Go and Rust SDK pin reconciliation not re-examined here |
| B: exact authority and request identity | VERIFIED IN THIS ENVIRONMENT (Airlock suites) | 2,377 integration tests; duplicate-key handling reviewed on every model path | Cross-implementation canonical corpus not rerun |
| C: external boundary | VERIFIED IN THIS ENVIRONMENT (macOS Docker Desktop); C1 also in Linux CI | 198 container tests including bypass attempts and credential isolation; independent containment | C2 on Linux (CI blocked); disk quota not enforced (documented) |
| D: effect ownership and recovery | VERIFIED IN THIS ENVIRONMENT (local host) | Effect durability, reconciliation and recovery suites | No multi-host claim |
| E: useful unchanged agent | **BLOCKED** | Historical live runs only, on other source | Experiments A–C on C2, after owner approval |
| F: install, review, independent evidence | PARTIAL | Clean wheel install; one entry point; reproduction harness; independent verifier (142 journals, 0 disagreements); tamper tests | Public-registry install (BLOCKED); two independent operators (NOT STARTED) |

## 3. Release bar

| # | Requirement | Status | Why |
|---|---|---|---|
| 1 | One candidate holding every supported agent | **PARTIALLY VERIFIED** | All suites pass locally at C2. C2's exact-head CI has not run (not pushed). The gate cannot read CI without authentication |
| 2 | Exact authority, enforced boundary, truthful effect ownership | **PARTIALLY VERIFIED** | As item 1 |
| 3 | A stranger can see it work, with no key and no cost | **PARTIALLY VERIFIED** | C1's CI stranger journey passed cold on Linux. C2 ran locally only |
| 4 | One entry point from task to reviewed patch | **PARTIALLY VERIFIED** | As item 1 |
| 5 | Real model, matched baseline, attacks from the same environment | **BLOCKED** | No run on C2. The historical pair is bound to `f04f60f`, under a different grant context |
| 6 | One real GitHub write, confirmed by independent readback | **BLOCKED** | No run on C2. The historical write is bound to `9fd8b94` |
| 7 | Three repositories and ten agent cases | **BLOCKED** | The original programme has a genuine FAIL (case 2) and 3 cases never run, and it is bound to `6868406`. A pre-registered v2 is needed |
| 8 | Install from public registries alone | **BLOCKED** (the gate reports FAIL) | Pre-release version; Git dependencies; nothing published |
| 9 | Two independent operators on fresh machines | **NOT STARTED** | Operator pack prepared and run end to end on this machine; no operator recruited |
| 10 | The owner accepts this bar | **PARTIALLY VERIFIED** | Accepted on 2026-11-01, and the pin matches in the candidate. But `main`, the gate's trusted checkout, has no bar, so the real gate cannot see it |

## 4. Historical evidence

See `HISTORICAL_ADJUDICATION.md`. In short:

- 28 of 37 modules, including the entire enforcement core, are byte-identical to the code the
  Gate 5, 6 and 7 live runs tested.
- Their findings are good evidence about those components.
- None can become C2's record: each is bound to another commit. Gate 5's grant context changed,
  and Gate 7's programme contains a genuine FAIL.

## 5. No-cost engineering

See `NO_COST_RESULTS.md`.

**Three defects found, reproduced and fixed** (NS-1 to NS-3). Each has a minimal reproducer, a
regression test that fails on C1, and passing suites on C2:

| ID | Defect |
|---|---|
| NS-1 | Airlock's verifier accepted a non-canonical, or duplicate-keyed, final receipt line |
| NS-2 | Two credential-isolation tests ran in no CI job |
| NS-3 | The trusted CI contract made items 1–4 FAIL on green CI |

**C2's suites** (local, frozen images):

| Suite | Result |
|---|---|
| Integration | 2,377 passed, 62 skipped (all allowed by its contract), 0 failed |
| Container job | 198 passed, 0 skipped |
| Independent containment | 1 passed |

**Exact-head CI:** C1 is green in run `42188115271`. C2 is not run.

**Admission gate:**

- With `main`'s rules: NOT READY, structurally. 29 G1–G40 gates are UNDEFINED.
- With the candidate's rules: NOT READY.

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
`reproduction/LOCAL_DRY_RUN.md`).

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

1. **Push C2** (owner runs `gh auth login`), open it for review, and get green exact-head CI on
   C2.
2. **Bring the trusted rules to `main`.** Merge the reviewed stack (PR #28 with C2), or a
   rules-only PR, with a merge commit, so the gate on `main` reads the bar and C2's CI contract.
3. **Decide the release commit question** (`REGISTRY_READINESS.md` R1–R2), then freeze the final
   evaluation commit.
4. **Run Experiments A, B and C** on that commit, each separately approved, then the owner
   reviews and writes records 5–7.

RELEASE READY additionally needs items 8 (publication) and 9 (two operators, bound to the
release commit).
