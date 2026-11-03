# V4.2 one-run live diagnostic — prepared, NOT AUTHORIZED

Do not reuse any V4 or V4.1 configuration. Generate a fresh configuration from the clean final PR head after local checks and exact-head CI pass. The delivery's `frozen-live-candidate.json` binds the full source commit/digest, installed dependencies, pinned component commits, immutable image digest, unchanged official Codex command, prices, runner/fixture hashes and original task tree. An adjacent SHA-256 manifest binds the delivered files. No credential belongs in either file.

The sole proposed run is `baseline --task token-bucket`: unchanged official Codex CLI 0.166.0, real `gpt-5.5-2026-04-23` inference through the supervisor Responses transport, original task and independent hidden tests. No task simplification, fixture inference, binary patch, protected second trial, automatic retry or multi-run programme is authorized.

Before execution, the owner must separately and explicitly approve this new source/freeze and one billable run. Establish an independently enforced cumulative spending ceiling outside this runner and a **$2 (2,000,000 micro-USD) maximum per-run estimated inference bound**. The runner enforces only its run estimate; `--authorized-usd 2` is not cumulative enforcement or proof of owner approval. Earlier approvals do not carry forward. Prior ambiguous holds are not evidence of settled provider charges or available cumulative budget. The owner must supply a fresh API credential solely to the trusted supervisor using their secret-management process; do not place it in the repository, image, command line, logs or agent environment.

After those prerequisites, the owner-controlled runner may use the following argument shape (this document is not a launcher):

```text
.venv/bin/python acceptance/codex-cli/run.py baseline
  --task token-bucket
  --image sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269
  --config <new V4.2 frozen-live-candidate.json>
  --out <new exclusive V4.2 evidence directory>
  --live --authorized-usd 2
```

The runner must compare the complete freeze with the current environment before dispatch. Check out its exact commit; preserve the same Python environment and pinned dependencies. Any source, dependency, image, command or task drift requires a new reviewed freeze. Do not weaken the comparison to accommodate a different environment.

Require agent exit **0**, runner exit **0**, all three visible and four independent hidden tests passing, and independently observed task execution results. Require completed internally consistent Responses with validated base usage, supported zero/default metadata, signed accounting and verified anchored receipts/checkpoint. Preserve run result, diagnostic receipt journal and public verification material; do not retain private bodies as a workaround for diagnostics. Verify receipt signatures independently and reconcile final billing separately. A refusal, ambiguity, incomplete stream, unsuccessful exit, missing execution evidence or failed hidden test fails this diagnostic: stop without automatic retries or another billable trial.

A passing single baseline is diagnostic evidence only. It does not satisfy every existing release gate. Do not merge, tag, publish or change the owner-accepted release bar.
