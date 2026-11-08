# No-cost exact-candidate verification (2026-11-08, macOS arm64, Docker Desktop 29.9.2)

All runs used a fresh, **non-editable** `pip install ".[test]"` into a new Python 3.12 venv, as
CI does, and the frozen images in `candidate-identity.json`. Raw logs, JUnit and verifier
output are in `~/src/actenon-audit/northstar-evidence/`; they are local, not committed.

## Candidate 1 (`67b348c`, PR #28 head at audit start)

| Run | Command (as CI) | Result |
|---|---|---|
| Integration | `pytest -q --junitxml=…` | **2,229 passed, 62 skipped, 0 failed** |
| Container job | the CI file list with the CI environment, frozen images | **190 passed, 0 skipped, 0 failed** |
| Independent containment | `pytest tests/test_independent_container.py` | 1 passed |
| Credential isolation (with the Codex image) | `pytest tests/test_supervisor_credential_isolation.py` | 8 passed; 2 of these run in **no** CI job (NS-2) |
| Exact-head CI on GitHub | run `42188115271`, read anonymously | all 6 jobs `success`, in one run |
| Admission gate, `main`'s rules | `check_candidate_admission.py --require "CANDIDATE READY"` | NOT READY: 29 G1–G40 UNDEFINED, 11 BLOCKED. `main` has no release bar |
| Admission gate, the candidate's rules | same, run in the candidate checkout | NOT READY: items 1–4 BLOCKED (no GitHub auth), 5–7 and 9 BLOCKED (no records), 8 FAIL (pre-release), 10 PASS |
| Skip set against the trusted contract | gate's own `junit_outcomes` | 37 skips not allowed by C1's contract, 60 not allowed by `main`'s (NS-3) |

## Defects found in C1 and fixed in C2 (`fix/north-star-blockers`, draft PR #29)

| ID | Guarantee affected | Minimal reproducer | Fix | Regression |
|---|---|---|---|---|
| **NS-1** | Evidence integrity: a receipt line must be the bytes that were signed | Reformat the final line, or prepend `"action":"TAMPERED",` to it. Airlock's verifier still says `ok` (Python keeps the last duplicate); the independent verifier rejects it | `state.py`: refuse a line unless it equals `canonical(row)` | `tests/test_receipt_canonical_lines.py` fails on C1 and passes on C2; all 142 committed journals still verify |
| **NS-2** | Credential isolation actually tested in CI | `tests/test_supervisor_credential_isolation.py` skips in the integration job and is absent from the container job | The container job runs it; its two key tests are `must_pass` | `tests/test_ci_contract.py` fails on C1 |
| **NS-3** | Release admission can evaluate a valid candidate | The trusted contract allows 25 (C1) or 2 (`main`) integration skips; the candidate legitimately skips 62 | All 62 are allowed only in the integration job and **required to pass** in the container job (`must_pass` 24 → 61; that job still allows 0 skips) | `tests/test_ci_contract.py` and `tests/test_candidate_admission.py` |

Not a defect, but checked: on the generic model path, the request is parsed once and dispatched
as `canonical(request)`, so policy and dispatch see the same object (goal B: normalise once).
The Claude Code and Codex contracts reject duplicate keys outright.

## Candidate 2 (`dc7ed54`; installable product `eba7ef7`)

| Run | Result |
|---|---|
| Integration | **2,377 passed, 62 skipped, 0 failed**; all 62 skips allowed by C2's contract |
| Container job (now including credential isolation) | **198 passed, 0 skipped, 0 failed**; all 61 required tests passed |
| Independent containment | 1 passed |
| C2 contract check (`reproduction/check_results.py junit`) | both artifacts OK |
| Documented install pin | `scripts/check_readme_install.py`: every guide pins `eba7ef7`, which installs C2's code |
| Exact-head CI | [Run 42519985401](https://github.com/Actenon/actenon-airlock/actions/runs/42519985401) (`pull_request`, head `dc7ed54`): **all 6 jobs success** |
| Independent CI verification (`verify_ci.py`) | Every artifact's bytes match GitHub's digest. Container reports: 198 + 1 passed, 0 skipped, all 61 + 1 required passed. CI installed exactly the four pinned dependency commits; pip-audit found 0 vulnerabilities. **Integration reports: 64 skips, and 2 are not allowed by C2's contract** (NS-4) |
| Source identity on GitHub | The digest of GitHub's tarball of `dc7ed54` and of the wheel CI built is `da323e93…`, with the same 37 files and identical bytes |
| What a `pull_request` run tests | GitHub's merge commit `d25e54b9…` has exactly C2's tree (`b0d37a76…`), so the run tested C2's bytes |
| Authenticated admission, C2's rules | dependency graph **PASS** (all four commits' required jobs passed). Bar items 1–4 **FAIL** (the two skips); 5–7 and 9 BLOCKED (no records); 8 FAIL (pre-release); 10 PASS |
| Authenticated admission, `main`'s rules | NOT READY: 29 UNDEFINED, 11 BLOCKED; `candidate_ci` FAIL |

**NS-4 (release admission could still not admit a green candidate).**

- **Which tests:** `tests/test_readme_install.py::test_the_repository_docs_pin_one_commit_that_installs_this_code`
  and `::test_an_older_product_commit_is_rejected`.
- **Why they skip:** both need the pinned product commit and its predecessor. The integration
  job checked out one commit, so on CI they skip.
- **Why NS-3 missed it:** NS-3's skip set was measured on a full-history clone, where both run.
- **Reproducer:** `git clone --depth 1` of C2 shows the same two skips with the same messages.
- **Fix in C3:** `fetch-depth: 0` on the integration checkout, as the documented-install job
  already has. The contract data is unchanged.
- **Regression test:** `tests/test_ci_contract.py::test_the_integration_job_has_the_history_its_required_tests_need`
  fails on C2's workflow.

## Candidate 3 (`5b1f0f2`; installable product `eba7ef7`, source digest unchanged)

C3 is C2 plus one commit. It changes `.github/workflows/ci.yml` and `tests/test_ci_contract.py`.
Everything else is byte-identical to C2:

- `src/`, `containers/`, `pyproject.toml` and `uv.lock`;
- `release/gates.json` and `release/RELEASE_BAR.md`;
- the admission and identity scripts;
- all four acceptance harness trees.

| Run | Result |
|---|---|
| The pin and contract tests, on a full-history simulation of GitHub's PR merge commit (tree identical to C3) | 19 passed, 0 skipped |
| Integration, fresh non-editable install (macOS, Python 3.12) | **2,378 passed, 62 skipped, 0 failed**; all 62 skips allowed by C3's contract |
| Gate 5 freeze (no cost) | `matched-freeze-5b1f0f2.json`, SHA-256 `a17308d0e15aef4509b164529edcd007cb62b6042ae400a9aa699da22f97e0f5`. Of its 84 fields, only `source_commit` differs from the C2 freeze |
| Exact-head CI | [run 42520916211](https://github.com/Actenon/actenon-airlock/actions/runs/42520916211) (`pull_request`, head `5b1f0f2`): **all 6 jobs success** |
| What a `pull_request` run tests | GitHub's merge commit `1c3448ad…` has exactly C3's tree (`124cde3e…`) |
| Independent CI verification (`verify_ci.py`) | **ok, no problems.** Every artifact's bytes match GitHub's digest. Integration 3.11 and 3.12: 2,440 cases each, 0 failed, 62 skipped, all allowed. Container: 198 passed, 0 skipped, plus independent containment 1 passed; all 61 + 1 required passed. CI installed exactly the four pinned dependency commits. pip-audit: 0 vulnerabilities in 54 packages |
| Source identity on GitHub | GitHub's tarball of `5b1f0f2` and the wheel CI built both give `da323e93…`, with the same 37 files and identical bytes. CI's wheel SHA-256 is `ab4af4af…` |
| Authenticated admission, C3's rules | **`candidate_ci` PASS. Bar items 1–4 PASS** (run 42520916211). Dependency graph PASS. Items 5–7 and 9 BLOCKED (no owner records), 8 FAIL (pre-release), 10 PASS. Overall **NOT READY** |
| Authenticated admission, `main`'s rules | NOT READY: 29 UNDEFINED, 11 BLOCKED. `candidate_ci` FAIL, because `main`'s contract allows 2 integration skips and the candidate skips the 62 real-container tests that its container job runs and passes |

## Independent offline verification

The verifier is `release/north-star/verifier/airlock_verify.go`: Go standard library only, with
its own canonical JSON and Ed25519 implementation. It was built offline with
`golang@sha256:2c4c60ef…` (go1.25.14), after `gofmt` and `go vet`.

- **Differential run over every committed journal:** 142 journals, 1,237 receipts.
  - **0 disagreements** with Airlock's verifier on integrity, entry count and chain head.
  - 75 journals are anchored by a checkpoint, 67 are unanchored.
  - 34 reconciliation rows have nested observer signatures that this verifier does not check,
    and it says so.
- **Tamper tests** on copies of the Gate 6 journal:

| Case | Independent | Airlock (C1) |
|---|---|---|
| Removed line, swapped lines, edited value, forged append, wrong key, incomplete final line | rejected | rejected |
| Truncated with a checkpoint | TRUNCATED | TRUNCATED |
| Truncated without a checkpoint | UNANCHORED (undetectable, as documented) | UNANCHORED |
| Final line reformatted, no checkpoint | **rejected** | **accepted** (NS-1) |
| Final line with a duplicate key, no checkpoint | **rejected** | **accepted** (NS-1) |

**Provider truth is reported separately.** A valid journal proves what Airlock recorded, not what
GitHub did. The Gate 6 records (the reviewed bytes, Airlock's readback and the owner's
separate-token readback) agree offline. Only someone with read access to the private repository
can confirm GitHub's state directly.

## Operator harness dry run (`reproduction/reproduce.sh`, fresh images)

- **All other checks matched `expected.json`.**
- **Two container tests failed once,** with `Docker operation failed: run`, under load. Reruns
  on the same images passed 7 of 7, and with the frozen images both passed in every full run
  today.
- **Classified INTERMITTENT ENVIRONMENT**, and kept as a reproducibility limitation: Docker
  Desktop sometimes refuses a `docker run` on a just-created IPv6 network under load. See
  `reproduction/LOCAL_DRY_RUN.md`.

## Release artifacts (Gate 8, dry run; nothing published)

See `REGISTRY_READINESS.md`. All five distributions build. The candidate's Airlock wheel
declares four direct Git dependencies, which PyPI refuses. A release-shaped variant (version
`0.1.0`, exact `==` pins) installs in a fresh venv from PyPI plus a local wheelhouse, with no
Git fetch, and `airlock doctor` is OK.

## Not exercised here (BLOCKED or out of scope)

- Linux container results for C3 come only from its exact-head CI. Locally, C3's container job
  was not rerun: its container tests, images and product code are byte-identical to C2's,
  which passed 198 + 1 locally and on Linux CI.
- The operator dry run (`reproduction/LOCAL_DRY_RUN.md`) was run against C2 and has not been
  repeated for C3.
- Linux x86_64 for C2: only C1 ran on Linux, in its exact-head CI.
- Cross-implementation canonicalisation corpus (Python, TypeScript, Go and Rust SDKs): not rerun
  in this programme. The last recorded comparison is in `release/candidate-manifest.json`.
- Shared-store, multi-host effect ownership: never claimed.
- Any model call or GitHub write: not authorised.
