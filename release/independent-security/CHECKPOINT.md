# Independent security continuation checkpoint

Branch: `codex/airlock-independent-security`. Base: `341ce3a2f10d2eafa5b07e74539a36e16d3dfac2`.

Implementation and regressions: `fe6d407a0728edac92a7e9e6408bd7ddec1d10a7`. The following evidence commit changes only reports and preserved results. Read REPORT.md and evidence/source-manifest.json before continuation. Original milestone and historical admission gates are preserved. Freshly fetch milestone updates before integration; do not modify another engineer's worktree.

The independent source worktree is `work/airlock-independent` beneath the originating Codex chat directory. Its separate clone is `work/airlock-git`; the test venv is `work/venv`. No shared original state was used. Docker image: `actenon-airlock-codex-assurance:20261030`. The unique test resources are cleaned up; public evidence remains under this directory.

Review focus: migration of prior header-dependent holds; store/journal reconciliation after interrupted completion appends; the intentional distinction between Local Mode byte-request holds and supported Protected Mode provider semantics. There is no configured authoritative external history store, so joint local history destruction remains a documented limit. There is no automatic legacy state migration in this change. Do not delete evidence or rotate keys to make startup pass.

No live-model acceptance result is claimed. Provider fixtures are labelled. No package, tag or deployment has been published, and no PR has been merged. Re-run the full suite with Docker enabled after any further implementation edit.

Final Airlock validation: 593 passed, zero skipped with Docker enabled; lint, formatting, build and clean-wheel diagnostics passed. Retained evidence is keyed to the implementation commit above.
