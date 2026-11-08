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

## Defects found and fixed (on `fix/north-star-blockers`, not pushed)

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
| Exact-head CI | **BLOCKED**: not pushed, because the GitHub CLI token is invalid |

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

- Exact-head CI for C2, and the admission gate's authenticated checks: they need `gh auth login`
  by the owner, then a push.
- Linux x86_64 for C2: only C1 ran on Linux, in its exact-head CI.
- Cross-implementation canonicalisation corpus (Python, TypeScript, Go and Rust SDKs): not rerun
  in this programme. The last recorded comparison is in `release/candidate-manifest.json`.
- Shared-store, multi-host effect ownership: never claimed.
- Any model call or GitHub write: not authorised.
