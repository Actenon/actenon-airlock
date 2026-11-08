# Release identity: the owner's revisions to D2, D6, D8 and D9 (2026-11-08)

**Owner decision:** D1–D9 approved with revisions.

- **Accepted:** D1 (Airlock `0.1.0`), D3, D4 and D7.
- **D5 accepted conditionally:** source-preserving merges, reviewed publishing workflows,
  artifact provenance, and separate approval for tagging and publication.
- **D2, D6, D8 and D9:** revised below, each with its implementation, adversarial tests and CI
  evidence.

**Nothing was merged, tagged, published or paid for, no GitHub consequence was created, and no
owner record was written.** C3 `5b1f0f2` and its verified CI evidence are unchanged.

**Goal:** one immutable C4b whose installed artifacts, security acceptance, independent evidence
and public release are demonstrably the same product.

## D2 (revised): Permit `2.0.0` final

**Minimum change.** A version-only commit on top of the pinned `85aa3ae` touches 10 lines in 6
files. It changes no code, test or dependency.

| File | Change |
|---|---|
| `pyproject.toml` | `version = "2.0.0"` (Permit's `__version__` comes from package metadata) |
| `uv.lock` | The project's own entry, `2.0.0` |
| `FINDINGS.md` | The staged-version waiver that `scripts/check_version_coherence.py` reads: `staged_version` `2.0.0`, `expires_at` within its 14-day bound (the current waiver expires today) |
| `CHANGELOG.md`, `SECURITY.md`, `docs/CAPABILITY_PROVENANCE.md` | The version they name |

The TypeScript SDK `2.0.0-rc.1` is a separate npm package with its own `ts-sdk-v*` tags, and is
unchanged.

**Why `2.0.0` fits Permit's own process better:** its coherence gate recognises only
`v<major>.<minor>.<patch>` release tags, so a `v2.0.0rc1` tag would not even count as a release.

**Exact-head tests** (local; the commit is in a scratch clone, **not pushed**):

| Check at the version-only commit `bc8788f` (parent `85aa3ae`) | Result |
|---|---|
| Permit's full test suite (Kernel `ead6a00` and Protocol `a2e0e08` installed from their pins) | **913 passed, 3 skipped, 0 failed** |
| `check_version_coherence.py --mode pr` | All assertions pass |
| `--mode main` | `CANDIDATE_STAGE_OK [RELEASE_BLOCKED]`, with the renewed waiver |
| `--mode release` | `RELEASE_BLOCKED`, correctly: no `v2.0.0` tag or PyPI release yet, and the waiver does not count for a release |

**Permit's CI on this exact head was not run.** That needs a push to `Actenon/actenon-permit`,
which this instruction did not authorise. The commit is preserved as a patch, `northstar-evidence/d2-permit-2.0.0/permit-2.0.0-version-only.patch`.

**Effects on dependency identity:**

- **Permit's approved source commit changes.** It is the Permit release commit, not `85aa3ae`.
  Permit's own rules also require `[tool.uv.sources]` (Git pins for Kernel and Protocol) to be
  removed and `uv.lock` regenerated against PyPI before release. So the release commit can only
  be made **after Kernel 1.3.0 and Protocol 1.6.0 are published**. Kernel's rules are the same
  for Protocol.
- **The wheel's package payload is unchanged.** With `SOURCE_DATE_EPOCH` at the commit time, the 2.0.0 wheel
(`5362a55d…`) and the rc1 wheel (`f3a553e8…`) have **byte-identical package payloads (51
files)**. The only metadata difference is `Version: 2.0.0rc1` to `Version: 2.0.0`, with the
`RECORD` and directory name that follow from it. So every Airlock test result on rc1 concerns
the same Permit code.
- **Airlock C4a also changes `src/actenon_airlock/cli.py`:** `doctor`'s expectation
  `"actenon-permit": "2.0.0rc1"` becomes `"2.0.0"`. So does the `==` pin.

## D6 (revised): registry dependencies cannot pass provenance vacuously

**Draft PR #33**, rules only, stacked on #32; CI green (run `42528162848`, all 5 jobs).

**The chain.** For each Actenon package locked from a registry, the gate requires every link,
and fails closed on any break:

1. **Approved source on `main`.** `registry_dependencies.packages` names the version, repository,
   full source commit and source root. The approvals are a separate reviewed change. #33 approves
   none, so a registry dependency FAILs today.
2. **Source CI.** The approved commit's reviewed jobs passed.
3. **Published files.** Each file `uv.lock` pins is on PyPI with that sha256. It is downloaded
   only from `files.pythonhosted.org`, and the bytes must hash to it. Optionally, the owner pins
   the exact artifact hashes.
4. **Content = source.** The files are compared with GitHub's tarball of the approved commit.
   - Every wheel payload file is byte-equal to source, and no source module is dropped.
   - There is exactly one `.dist-info`, no `.data`, and the metadata names the version.
   - Every sdist member is byte-equal to source, or is generated metadata.
5. **Installed = locked.** Every mandated pip installation report (integration 3.11 and 3.12,
   container) shows exactly a locked wheel, from PyPI.
6. **No partial or empty graph.** Every reviewed dependency repository must be locked, and none
   twice.

| Evidence | Result |
|---|---|
| Gate tests | 122 pass, including 35 adversarial cases: wrong source; modified, extra or dropped files; wrong metadata; sdist tampering; a hash not on PyPI; swapped bytes; pinned-hash mismatch; failing or missing source CI; the wrong installed hash; an install from outside PyPI; a missing, non-pip or incomplete report; an unlocked package; a double lock; an empty or partial lock; malformed approvals |
| Mutation check | Wheel content, sdist content, the CI-install check, completeness, download hashing and source CI were each disabled in turn, and **every one was caught** |
| Real artifacts | The four wheels and four sdists rebuilt at the pins are **PROVEN** against GitHub's tarballs. A Kernel wheel checked against Scan's commit FAILs |
| C3 under the D6 rules | Unchanged: 4 Git dependencies proven, and the same bar result |

## D8 (revised): versioned identity harness that recognises registry artifacts

**Candidate branch `release/registry-path`, draft PR #34 (stacked on #31).**

**The module.** `acceptance/dependency_identity.py` (identity **v2**, standard library only)
replaces the `direct_url.json` read in the Gate 5/6 runner (`acceptance/claude-code/run.py`,
reused by Gate 6) and in the Codex runner.

- **Git-locked:** installed from exactly the locked commit. v1 only recorded the commit; v2
  also compares it with the lock.
- **Registry-locked:** the locked version, installed from a registry rather than from source.
  - Every installed file is hashed and matched to `RECORD`.
  - The (path, sha256) set must equal the contents of exactly one locked wheel.
  - Wheel bytes are taken from a content-addressed store only if they hash to the locked digest.
    Otherwise they are fetched from PyPI only.

**Versioning.**

- The runners record `identity_version: 2`, the identity schema and `candidate_dependencies`.
- The module is added to their programme hashes, so a freeze binds it.
- Every result schema, pass rule and original Gate 5/6 criterion is unchanged.
- Historical harnesses and evidence are untouched.
- The frozen Gate 5 experiment is not re-run or altered. Its freeze is made afresh at C4b.

**Tests:** 13 pass.

- **Refused:** an edited file; an edit hidden by a rewritten `RECORD`; another build; another
  version; a Git install under a registry lock; an index install under a Git lock; the wrong
  locked commit; untrusted store bytes and non-PyPI URLs; an unlocked dependency.
- **Recognised:** registry installs without `direct_url.json`; a **real pip index install**;
  this environment against its own lock.

## D9 (revised): the security suites pass on registry-installed artifacts

**Same branch.**

- **Locked installs.** `scripts/install_candidate.py` installs exactly what `uv.lock` pins.
  - For registry locks: `uv export` with hashes, then `pip install --require-hashes --no-deps`,
    then a check that pip's report names only locked wheels.
  - Either way, it writes pip's installation report for the D6 gate.
- **Contract jobs.** The integration and container jobs use it and upload `install-report.json`.
- **Registry rehearsal** (new job). Before publication, a hashed local index of wheels built at
  the exact pinned commits stands in for PyPI.
  - Each wheel is verified against its commit with the gate's own content check.
  - The tree is locked with uv and committed locally, with the docs re-pinned. This is never
    pushed.
  - It installs by sha256 and runs **the full integration suite, the same container security
    suite and independent containment** on that install.
  - Git installs are not the only path to green.
  - On C4b itself, the contract jobs install from PyPI, so the registry path is the mandated
    path. A Git-source job may remain for comparison only.

| Evidence | Result |
|---|---|
| Local rehearsal of the job's exact sequence (macOS) | All 4 wheels PROVEN against their commits. `uv.lock` records `source = { registry }` with sha256s, and pip installed exactly the locked hashes (Kernel `d39e7c5c…`, Permit `f3a553e8…`, Protocol `e7c93a7e…`, Scan `9ecd7cce…`, equal to independent rebuilds). The tree stays clean. **Full integration suite on the registry install: 2,429 passed, 62 skipped (all allowed by the contract), 0 failed.** That includes the credential-isolation runner-identity test, which failed on registry installs before D8 |
| Exact-head CI at `5c8c70f` (run `42529173264`) | **Failed in the registry rehearsal only**, on 1 of 198 container tests: `test_gate5_matched_programme::test_matched_rehearsal_both_modes`. The frozen runner runs under `referee.py`, which scrubs its environment, so the store pointer `AIRLOCK_ACCEPTANCE_ARTIFACTS` never arrived. Identity v2 then refused, as designed: the rehearsal's locked URLs are on `127.0.0.1`, not PyPI. Every other job passed: integration 3.11 and 3.12, container, documented install, and package. The rehearsal's integration suite passed in full (2,491 cases, 0 failed) |
| Fix, `4386649` (CI only) | The rehearsal seeds identity's default content-addressed store with the rehearsal wheels; the harness, referee and fail-closed rule are unchanged. Locally the Gate 5 programme and credential-isolation files pass on the registry install (24 passed) |
| Exact-head CI at `4386649` (run `42530235801`) | **All 7 jobs success.** Integration 3.11 and 3.12, container, documented install 3.11 and 3.12, package, and the **registry rehearsal** |
| Independent verification (`verify_ci.py`, extended for install reports and the rehearsal) | **ok, no problems.** All 7 artifacts match GitHub's digests. Contract jobs: 2,491 + 2,491 integration cases (0 failed, 62 allowed skips) and 198 + 1 container cases (0 failed, 0 skipped). All three install reports record exactly the four locked commits. **Rehearsal, scored against the same contract: integration 2,491 (0 failed, 62 allowed skips), container 198 (0 failed, 0 skipped), independent 1 (0 failed)** |
| Rehearsal artifacts | All four wheels were built on GitHub's Linux runner at the pinned commits and PROVEN against them. pip installed exactly those sha256s by `--require-hashes`. They are **identical to the macOS rebuilds** (`d39e7c5c…`, `f3a553e8…`, `e7c93a7e…`, `9ecd7cce…`), so with `SOURCE_DATE_EPOCH` and `build==1.2.2.post1` the artifact hash is predictable from the source commit on either platform |
| Authenticated gate, D6 rules (#33 checkout), at `4386649` | `candidate_ci` PASS; dependency graph PASS (4 Git dependencies, equal to the expected pins); items 1–4 and 10 PASS; 5–7 and 9 BLOCKED; 8 FAIL (pre-release); overall NOT READY, as expected for a pre-release branch |

## The final release sequence: one immutable C4b

| # | Step | Who | Reversibility |
|---|---|---|---|
| 1 | Merge #32 (the accepted bar and CI contract) into `main`, then #33 (D6) | Owner | Merges |
| 2 | Review and merge `release/registry-path` (D8, D9) into the candidate line | Owner | Merge |
| 3 | **Protocol 1.6.0:** merge PR #26 with a merge commit; tag `v1.6.0` at `a2e0e08`; publish | Owner, separately approved | **Irreversible** |
| 4 | **Scan 1.6.0:** merge #103 with a merge commit; tag `v1.6.0` at `1638822`; publish | Owner, separately approved | **Irreversible** |
| 5 | **Kernel 1.3.0 release commit:** `ead6a00` minus `[tool.uv.sources]`, `uv.lock` against PyPI, waiver renewed. Then its CI, a D6 content check (no package file may change), merge #51/#52 with merge commits, tag `v1.3.0` at it, publish | Owner, separately approved | **Irreversible** |
| 6 | **Permit 2.0.0 release commit:** D2's version change plus removal of `[tool.uv.sources]` and `uv.lock` against PyPI. Then its CI, merge #38, tag `v2.0.0`, publish | Owner, separately approved | **Irreversible** |
| 7 | Provenance check on each publication: the D6 content check against the PyPI files; optionally record their hashes | No cost | — |
| 8 | A reviewed rules PR to `main` adding the four `registry_dependencies.packages` approvals (optionally with `artifact_sha256`) | Owner | Merge |
| 9 | **C4a:** `version = "0.1.0"`, `__version__`, `doctor` expectations (Permit `2.0.0`), `==` pins, `uv.lock` against PyPI with `uv lock --check` clean. The rehearsal job is retired, because the contract jobs now take the registry path | No cost | — |
| 10 | **C4b:** the docs re-pin to C4a. **C4b is the final evaluation SHA, and is immutable from here** | No cost | — |
| 11 | Exact-head CI on C4b (registry installs by hash), independent verification, and the authenticated gate from `main`. Expect items 1–4 PASS, the dependency graph PASS through 4 proven registry dependencies, item 8 PASS and item 10 PASS | No cost | — |
| 12 | Gate 5 freeze at C4b with harness v2. The live venv is built exactly like CI, through `install_candidate.py` from PyPI, so the freeze records the same artifact hashes CI installed. Then Experiment A, **separately authorised** ($4 cap, 2 trials), then B and C | Owner approval | Paid; GitHub writes (B, C) |
| 13 | Owner records 5–7 for C4b, each a reviewed PR to `main` with its evidence | Owner | — |
| 14 | Item 9: two independent operators on C4b, using the pack updated to install like CI | Operators, owner | — |
| 15 | `release.yml` and its request check to `main`; owner setup of the `pypi-release` environment, trusted publisher and tag ruleset | Owner | Merge, settings |
| 16 | Dispatch `release.yml` from `main` for C4b and `0.1.0`: admission must be RELEASE READY; then build, attest, publish, and tag `v0.1.0` at C4b | Owner, separately approved | **Irreversible** |
| 17 | **Same-product check:** a registry-only install of `actenon-airlock==0.1.0` in a clean environment | No cost | — |

Step 17 must show:

- the published Airlock wheel's source digest equals C4b's;
- its build attestation names C4b;
- identity v2 shows the installed dependencies are the locked artifacts that CI and the live
  runs used.

**Why this is one product:** each link names the same bytes.

- C4b's `uv.lock` pins the dependency hashes.
- The trusted gate binds those hashes to approved source commits and to what CI installed.
- The live freeze binds the same hashes to what the experiments ran.
- The release workflow publishes Airlock built from C4b, attested to C4b.

Any change after step 10 makes a new commit, and every record, freeze and verification binds to
the exact commit.

## Not yet demonstrated (each needs authorisation or publication)

- **Permit's own CI at the 2.0.0 version-only commit.** It needs a push to
  `Actenon/actenon-permit`, which was not authorised. Its full suite passed locally.
- **The Kernel and Permit release commits** (removing `[tool.uv.sources]`, with `uv.lock` against
  PyPI). They cannot be made until their upstreams are published.
- **The D6 registry chain against real PyPI files, real install reports and owner approvals.**
  It is proven here against real rebuilt artifacts, GitHub's real tarballs and adversarial
  fixtures, but the first real run is C4b's.
- **Registry installs from PyPI itself.** The rehearsal stands in for PyPI with a hashed local
  index serving the same bytes, on the same lock and install path.
- **Identity v2 fetching from PyPI** (used only when a locked wheel is absent from the store),
  and every live run.
