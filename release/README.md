# Release admission

`scripts/check_candidate_admission.py` decides whether an Airlock commit is
`NOT READY`, `CANDIDATE READY` or `RELEASE READY` against the G1-G40 programme.
It is enforced by `.github/workflows/release-admission.yml` (manual dispatch with
a mandatory threshold, and every `v*` tag at `RELEASE READY`). It exits 1 when the
candidate falls short of `--require` and 2 when it cannot evaluate at all.

## Where each PASS comes from

| Evidence | Producer | Bound by | Trusted issuer |
|---|---|---|---|
| Candidate CI jobs | `ci.yml` jobs named in `gates.json` | check run -> workflow run (`path`, `head_sha`, same-repo head) | GitHub Actions API |
| Test reports | JUnit artifacts from that run | artifact `workflow_run.head_sha`; bytes = server `sha256` digest; skip allowlist | GitHub Actions API |
| Dependency graph | each repo's CI on the commit pinned in the candidate `uv.lock` | `uv.lock` read from the candidate commit object; optional `--expect-dependency` | GitHub Actions API |
| G28-G38 frozen programme | `real-coding-acceptance.yml` | run on the candidate commit; artifact digest; Sigstore provenance (`gh attestation verify --signer-workflow --source-digest --deny-self-hosted-runners`); frozen model, digest, agent revision and harness hashes; `airlock_dependency_manifest_sha256` = candidate `pyproject.toml` | GitHub Actions OIDC + Sigstore public-good |
| Registry coherence (release only) | PyPI JSON API | final version, no git/URL dependencies, locked hashes published | PyPI |

Local files are never read as evidence. The rules (`gates.json`, the frozen
definitions) come from the checkout running the gate, so dispatch it from `main`.

## Recovered scope (A-F)

`release/recovered/ACTENON_WORK_EXECUTION_GOAL.md` is the owner-recovered goal
document, committed verbatim and pinned by SHA-256 in `gates.json`. Its
mandatory sections A-F are candidate prerequisites. None has an automated
evidence producer yet, so each is BLOCKED, and a changed document FAILs all six.
`gates-recovered-v2.proposed.json` breaks A-F into requirements with a current,
self-assessed status for owner review. The gate does not load it.

## Current blocker: the frozen G1-G40 text is not committed

No Actenon repository contains the verbatim G1-G40 acceptance criteria. Only
G28-G38 can be identified (the frozen gpt-engineer / `qwen2.5-coder:14b`
matched-baseline programme), and only at programme level, so those eleven gates
share one evidence run and are labelled as such. G1-G27, G39 and G40 are
`UNDEFINED`. To unblock: commit the verbatim text as `release/G1-G40.frozen.md`,
pin its SHA-256 in `gates.json`, and give each gate its condition and evidence
producer in a reviewed change.

## Acceptance v2

`acceptance-v2/` is a separately versioned programme with its own specification, frozen
config, evidence and [verdict](acceptance-v2/VERDICT.md). The gate does not load it, and
it does not replace, pass or amend G1-G40.

## Limits

* An attestation proves which workflow and commit produced a file, not that its
  claims are true. A candidate that rewrites its own harness could emit a false
  summary from a genuine run; the frozen harness hashes narrow that, and harness
  changes still need review.
* The compute image ID is recorded, not independently rebuilt.
* GitHub, its Actions OIDC issuer, Sigstore and PyPI are trusted. Anyone with
  write access can change workflows on a branch; branch protection on `main`
  (owner action) is what makes "dispatch from main" meaningful.
