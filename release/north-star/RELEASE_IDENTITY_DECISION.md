# Release identity (R1/R2): what must be decided to freeze the final evaluation SHA

**Prepared 2026-11-08. Nothing here is decided, published or tagged.** C3
`5b1f0f29dba683c6a4f40d74ea404183224e3c7d` and its verified CI evidence (run 42520916211) are
preserved unchanged.

## 1. The answer in brief

- **The final evaluation commit cannot be C3.** A publishable release needs:
  - a final version;
  - registry dependency pins;
  - a lockfile against PyPI;
  - `__version__` changed in `src/` (so even the source digest changes);
  - a documentation pin to the new product commit.

  Release-bar records bind to the exact commit, so any live run on C3 would have to be
  repeated.
- **That commit cannot exist before the four dependencies are on PyPI.** The lockfile, the
  release commit's CI and bar item 8 all need the published files (section 2).
- **So the order is:**
  1. publish the dependencies;
  2. create the release commit C4 (two commits: C4a release metadata, C4b docs pin) and verify
     it at no cost;
  3. freeze C4;
  4. run Experiments A, B and C once, on C4;
  5. collect owner records and operators on C4;
  6. publish Airlock from C4 last.

## 2. Do registry hashes require publishing the dependencies first? Yes

| Reason | Evidence |
|---|---|
| The gate's item 8 needs every locked `actenon-*` file hash to be on PyPI | `check_registry_coherence`: `locked <= published`, and "is not published on PyPI" FAILs |
| `uv.lock` records each registry file's `url` and `upload-time` | C3's `uv.lock` (revision 5) has `hash`, `size`, `upload-time` and `url` per file. The last two exist only after upload |
| The release commit's own CI cannot pass until then | The documented-install job (bar item 3) does a cold `pipx install` of the pinned product commit, which fetches the four packages from PyPI. Under D9 (a) the integration and container jobs pre-install them from their pinned commits, but the cold install cannot |
| Predicting the hashes is not reliable | With `SOURCE_DATE_EPOCH` set to the commit time, local wheels rebuild byte-for-byte for all four (below). But each sibling publishes from its own tag-triggered CI with unpinned build tools, and only Kernel sets `SOURCE_DATE_EPOCH`. The setuptools sdists (Protocol, Kernel, Scan) are not reproducible even locally |

Local reproducible wheels at the pins (`python -m build` 1.2.2.post1, `SOURCE_DATE_EPOCH` = the
commit time, built twice each):

| Package | Pinned commit | Wheel SHA-256 (identical both builds) | sdist |
|---|---|---|---|
| actenon-protocol 1.6.0 | `a2e0e08f…` | `e7c93a7e156e4a7b27ef43999adfb3dd58acfc54ed49d605bfa5c9a0180e2124` | not reproducible |
| actenon-kernel 1.3.0 | `ead6a00a…` | `d39e7c5cfddd6780e47449f139cef6ae4d7c24018af5028a93149926d26cdbd3` | not reproducible |
| actenon-permit 2.0.0rc1 | `85aa3ae2…` | `f3a553e8eb25ca2e80d896f7c6162bc1e8a5c5e8eb6ff99f4f41365cca3a2431` | reproducible (`84f95e2a…`) |
| actenon-scan 1.6.0 | `16388227…` | `9ecd7cce290278dfb7d8ffd03417af25b47df2c76a342a54f5aaaf9996c66b60` | not reproducible |

These hashes are a provenance reference, not the hashes PyPI will hold. After publication,
compare the published wheels' contents with `git archive` of the pinned commits (D6).

## 3. The decisions

| # | Decision | Constraint found | Recommendation |
|---|---|---|---|
| **D1** | Airlock release version | Both enforcing paths reject a pre-release: the gate's item 8 FAILs `.devN`, `aN`, `bN`, `rcN` and `+local`, and `release.yml` (`check_release_request.py`) requires `^\d+\.\d+\.\d+$`. **No Airlock pre-release version can be the release candidate.** Operators need no published pre-release: the reproduction pack installs the exact commit | **`0.1.0`**, in both `pyproject.toml` and `src/actenon_airlock/__init__.py`. That is a one-line source change, so the source digest changes. A TestPyPI rehearsal is optional and not required |
| **D2** | Permit version | The gate checks pre-release status for Airlock only. `actenon-permit==2.0.0rc1` installs from an exact pin (shown in the dry run). `2.0.0` final would need a new Permit commit (version bump), its own CI and review, before publication | **`2.0.0rc1`**, published from the exact CI-tested commit `85aa3ae`. The cost is that a final Airlock depends on a release-candidate Permit; choose `2.0.0` if that signal is unacceptable |
| **D3** | Other dependency versions | Protocol 1.6.0, Kernel 1.3.0 and Scan 1.6.0 are the versions at the pins, and none is on PyPI yet (latest: 1.4.0, 1.2.1, 1.5.0) | Publish exactly these, from the pinned commits |
| **D4** | Airlock's registry pins | Direct URL dependencies FAIL item 8 and the release request | `actenon-scan==1.6.0`, `actenon-protocol==1.6.0`, `actenon-kernel==1.3.0`, `actenon-permit==2.0.0rc1` (exact `==`). `requests` and `httpx` ranges unchanged |
| **D5** | Which commits are published | Each sibling publishes on a `v*` tag push (trusted publishing). The pins are open-PR heads: Protocol #26, Kernel #51/#52, Permit #38, Scan #103. Kernel's pin has diverged from Kernel `main`: `main` has squash commit `498265b8c` (#50), but every file #50 touched is already identical in the pin | Merge each sibling PR **with a merge commit**, not squash, so the pinned commit is on the default branch. Then tag **the pinned commit itself**: `v1.6.0` at `a2e0e08`, `v1.3.0` at `ead6a00`, `v2.0.0rc1` at `85aa3ae`, `v1.6.0` at `1638822`. The published code is then the code tested here |
| **D6** | Dependency provenance after the switch | With registry pins, `uv.lock` has no Git sources, so the gate's `dependency_graph` passes vacuously ("0 locked candidate dependencies"). The bar says "their dependency graph must also pass" | For this release, record owner-reviewed provenance evidence: the pinned commits' required CI passed (C3's authenticated admission), and each published wheel's contents equal `git archive` at its pin. Optionally, a later, separately reviewed rule change maps registry pins to source commits. Do not change the rules silently |
| **D7** | Lockfile | CI never runs uv, so nothing checks `uv.lock` against `pyproject.toml` | After publication, regenerate with one recorded uv version against `https://pypi.org/simple`. Require no Git sources, every `actenon-*` entry from the registry with its hashes on PyPI, and `uv lock --check` clean |
| **D8** | Live-run environment on C4b | The frozen Gate 5 harness (`acceptance/claude-code/run.py` `identity()`, and the Codex one) reads each dependency's `direct_url.json` → `vcs_info.commit_id`. A PyPI install has no `direct_url.json`, so the unchanged freeze cannot run against registry-installed dependencies | Keep the experiment frozen. Build the live venv by installing the four dependencies from their pinned commits first, then C4b. Their code equals the published wheels (D6), and the freeze records the same four commits as now. **Rehearsed at no cost:** on the release-shaped rehearsal commit, the unchanged freeze succeeds with this venv. Of its 84 fields, 3 differ from the C3 freeze: Airlock's version, the commit and the source digest. The dependency commits, image, model, prices and programme hashes are identical. Gate 6's harness reuses the same `identity()` and needs the same venv; Gate 7's records installed versions only and works either way |
| **D9** | CI on the release commit | **The same limitation would turn C4b's CI red.** With registry-installed dependencies, `tests/test_supervisor_credential_isolation.py::test_runner_identity_git_and_docker_do_not_inherit_supervisor_secrets` fails: `TypeError` from `run.identity()` reading `direct_url.json`. That file runs in the integration job and, since NS-2, in the container job, so items 1–4 would FAIL | **(a) Recommended:** C4a's `ci.yml` installs the four dependencies from their pinned commits before `pip install ".[test]"`, in the integration and container jobs, with a contract test that these pins equal the published versions' source commits. The frozen harness stays unchanged. The registry path stays covered by the documented-install and package jobs and by step 14. **(b)** Change `run.identity()` to identify registry installs. That changes the frozen Gate 5 and Gate 6 harnesses (new programme hashes), so it needs explicit owner approval; not recommended |

## 4. Sequence that runs live acceptance only once

| Step | What | Who | Cost or reversibility |
|---|---|---|---|
| 1 | Merge PR #32 (rules on `main`) | Owner | Merge; reversible by revert |
| 2 | Decide D1–D7 | Owner | — |
| 3 | Merge the four sibling PRs with merge commits (D5) | Owner | Merges |
| 4 | Tag and publish Protocol, Kernel, Permit and Scan from the pinned commits, in dependency order | Owner | **Irreversible** (versions cannot be re-uploaded) |
| 5 | Provenance check (D6): compare the published wheels with the pins | No cost | — |
| 6 | Create C4a: `pyproject.toml` (D1, D4), `__init__.py` (D1), `uv.lock` (D7), and `ci.yml` plus its contract test (D9) | No cost | — |
| 7 | Create C4b: re-pin the documented install to C4a (`check_readme_install.py --pin`). **C4b is the final evaluation SHA** | No cost | — |
| 8 | Push C4b, run exact-head CI, verify independently, and run the authenticated gate from `main`. Expect items 1–4 PASS, and **item 8 PASS** (it checks the dependencies only) | No cost | Push |
| 9 | Re-freeze Gate 5 at C4b, then Experiments A, B and C, each separately approved | Owner approval | Paid; GitHub writes (B, C) |
| 10 | Owner records 5–7 for C4b, each a reviewed PR to `main` with its evidence | Owner | — |
| 11 | Item 9: two operators run the pack against C4b, then the owner record | Operators, owner | — |
| 12 | Bring `release.yml`, `scripts/check_release_request.py` and `release/settings/` to `main`; owner sets up `pypi-release`, the trusted publisher and the tag ruleset | Owner | Merge, settings |
| 13 | Dispatch `release.yml` from `main`: admission (RELEASE READY), build, attest, publish Airlock 0.1.0, tag `v0.1.0` at C4b | Owner | **Irreversible** |
| 14 | Registry-only install of `actenon-airlock==0.1.0` in a clean environment, with hashes checked against the release attestation | No cost | — |

If a defect turns up at step 8 or later, it needs a new commit, and records bind to the new
commit. If the defect is in a dependency, it also needs a new dependency version, because
published versions are immutable. That risk is inherent. The no-cost rehearsal (section 6)
exists to surface it before step 4.

## 5. The trusted admission precondition

- **After PR #32 merges:** `main`'s gate evaluates any candidate under the accepted bar.
  - Verified: with the PR's branch as the trusted checkout, C3 gets the same result as under its
    own rules. Items 1–4 and 10 PASS, 5–7 and 9 BLOCKED, 8 FAIL; overall NOT READY.
  - This satisfies `LIVE_PROGRAMME.md` step 1's "trusted rules on `main` must evaluate it" for C4b
    too, because the rules do not change between C3 and C4.
- **Publishing (step 13) needs more on `main`:** `release.yml` and its request check. That is not
  needed for admission or for live acceptance.

## 6. No-cost release-shaped rehearsal

This was run before anything irreversible, on local, unpushed scratch commits built from C3. It
is not a candidate. Evidence: `~/src/actenon-audit/northstar-evidence/release-rehearsal/`.

| Rehearsal | Result |
|---|---|
| Release-shaped commit `ba866d6` (C3 + `version = "0.1.0"`, `__version__ = "0.1.0"`, the D4 pins) | `scripts/check_release_request.py --version 0.1.0` **accepts** it. `airlock --version` prints `0.1.0` |
| Installed from PyPI plus the four locally rebuilt wheels (registry-style, no Git) | `airlock doctor` OK, with all four component versions as expected |
| Full suite with that registry-style install | **2,376 passed, 62 skipped, 2 failed.** (1) `test_readme_install`: the docs still pin `eba7ef7`, which is expected and why C4b exists. (2) `test_runner_identity_git_and_docker_do_not_inherit_supervisor_secrets`: the D8/D9 limitation |
| Unchanged Gate 5 freeze, dependencies installed from their pinned commits (D8) | **Succeeds.** Only Airlock's version, the commit and the source digest differ from the C3 freeze |
| Simulated C4b (`aa76adc`: plus `check_readme_install.py --pin`), dependencies from their pinned commits (D9 a) | **2,378 passed, 62 skipped, 0 failed**; every skip is allowed by the contract. With D9 (a), the release shape needs no other change |

Not rehearsable before publication: `uv.lock` (D7), item 8, and CI on GitHub.

## 7. Rejected alternatives

- **Live acceptance on C3, then rebinding to C4:** the bar forbids it ("Any later commit needs a
  new record").
- **Binding records by source digest instead of commit:** this would amend the frozen bar, and
  C4's source differs anyway (`__version__`).
- **Hand-computing the final lockfile before publication:** unknowable `upload-time` and `url`
  fields, and CI could still not install.
- **An Airlock pre-release (rc) as the release candidate:** fails item 8 and the release request.
