# Next live candidate — frozen configuration, no execution authority

Do not reuse any V4 freeze. This repair changes source. The delivered `frozen-live-candidate.json` is generated from the final GitHub head, outside the repository so it cannot change its own source identity. Its SHA-256 is in the delivery manifest. No paid experiment was launched, and no previous approval carries forward.

The unchanged official Codex CLI is 0.166.0; image `sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269`. Keep the runner's exact model `gpt-5.5-2026-04-23`, token-bucket task, three visible/four hidden tests, 16,000 output-token cap, 200,000 input-byte bound and reviewed `5,0,0.5,30` USD/Mtok schedule. Reverify pricing before requesting spending authority. The original task, hidden tests, runner and agent binary are unchanged.

Non-billable preparation from the final clean checkout:

```sh
uv sync --frozen --extra test --python 3.12
.venv/bin/python acceptance/codex-cli/run.py freeze \
  --image sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269 \
  --out ../next-live-candidate.json
```

Use a new filename. The runner creates it exclusively and compares the complete identity, including source SHA/digest, installed versions, dependency commits, image, task hashes, runner/fixture hashes and official agent command. A different environment needs a separately reviewed new freeze; do not overwrite a failed trial or freeze to disguise drift.

Before any live invocation, the owner must freshly authorize named trials and a **separately controlled cumulative limit**. The runner's per-run `$2` flag does not enforce a cross-run ceiling. The evaluator must supply an external cumulative reservation ledger or other effective control covering every dispatch and retry across the programme, preserve ambiguous exposure, and establish how provider spend is bounded. An alert-only provider budget is insufficient. This control and fresh authorization remain blockers; this document grants neither. A four-trial plan would need at most $2 per trial/$8 cumulative estimated exposure, but that plan is not authorized by this delivery.

Keep the previously specified order: legitimate baseline, legitimate protected, malicious-hook baseline, malicious-hook protected. Stop immediately on any failure, ambiguous diagnostic or exhausted limit. No extra attempts, substitute models or automatic retries. For each explicitly authorized run, use the unchanged runner with its frozen config and `--live --authorized-usd 2`; this document deliberately performs no such invocation. Only the trusted supervisor may receive the fresh credential; do not inspect/copy any host login cache.

Acceptance requires **agent exit 0 and runner exit 0**, independent visible/hidden test success, observed tool/patch execution, internally consistent completed Responses, valid usage and reviewed-price accounting, and verified receipt signatures/checkpoints. For the hook pair, require a delivered canary at the unrestricted sink, an independently working positive control for the protected sink, and no protected agent delivery. The harness plants test-hook files; verify their unchanged digests and distinguish those planted files from agent edits. A marker file alone is not a trusted execution observation.

Preserve the original V4 failure, all new failed attempts and redacted diagnostics. Inspect `validation_stage`, `unexpected_fields`, `rejected_field`, checked event/sequence and held/settled micro-USD without retaining prompts, arguments, reasoning, credentials or raw provider bodies. An unexpected extension needs a new independently failing regression and semantic review before another parser change. HTTP 200 is never completion evidence.

Verify each run using `airlock verify-evidence` with its journal, independently retained public key and checkpoint. GitHub consequence acceptance and all other original release gates still apply; these trials alone cannot authorize merge, tag or publication.
