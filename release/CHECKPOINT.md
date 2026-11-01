# Release candidate checkpoint

Branch `feat/airlock-release-candidate`, draft [PR #20](https://github.com/Actenon/actenon-airlock/pull/20) against `feat/airlock-milestone-1`. Status: **NOT READY**. No designation is awarded. Nothing is merged, tagged, published or deployed, and no paid inference or live GitHub write has happened.

The owner accepted the [release bar](RELEASE_BAR.md) on 2026-11-01. The gate checks it, and that takes effect when this reaches `main`.

## Resume

```bash
git checkout feat/airlock-release-candidate
```

```bash
uv venv -p 3.12 .venv && uv pip install -e ".[test]"
```

```bash
docker build -f containers/Dockerfile.compute -t actenon-airlock-compute:dev .
```

```bash
docker build -f containers/Dockerfile.claude-code -t actenon-airlock-claude-code:v1 .
```

```bash
docker build -f containers/Dockerfile.codex-cli -t actenon-airlock-codex-cli:v1 .
```

```bash
AIRLOCK_TEST_PROTECTED_IMAGE=actenon-airlock-compute:dev AIRLOCK_TEST_CLAUDE_CODE_IMAGE=actenon-airlock-claude-code:v1 AIRLOCK_TEST_CODEX_IMAGE=actenon-airlock-codex-cli:v1 .venv/bin/python -m pytest -q
```

See it work, with no key and no cost:

```bash
.venv/bin/airlock demo
```

## Where each bar item stands

| # | Requirement | Status | What it needs |
|---|---|---|---|
| 1-4 | Candidate, boundary, demo and one command | **Done** | Nothing |
| 5 | A real model, a matched baseline and attacks | **Not run** | Paid inference: $2.00 for the first slice, at most $62.00 in all for Claude Code, and at most $8.00 for Codex. See [LIVE_RUN.md](acceptance-claude-code/LIVE_RUN.md) |
| 6 | One real GitHub write | **Not run.** Passes against the synthetic provider | The owner's go-ahead, a disposable repository and a token limited to it. See [LIVE_TEST.md](acceptance-v2/LIVE_TEST.md) |
| 7 | Three original repositories and ten agent cases | **Not run** | The owner names the repositories. At $2.00 a run with a matched baseline, at most $40.00 |
| 8 | Install from public registries alone | **Blocked** | The owner merges the Kernel and Permit candidates and publishes the packages and images |
| 9 | Two independent operators on fresh machines | **Blocked** | Two people outside this work. The [reproduction guide](../acceptance/v2/README.md) is what they follow |
| 10 | The owner accepts the bar | **Done** on 2026-11-01 | Nothing |

Also open, outside the bar: show that real Aider exits 0 with a real model. The repeated-inference fix has a real-boundary test with an SDK client and a failing reproduction on the scored wheel. The confirming run was stopped because 14B made the Mac unusable, and a scripted model could not reproduce Aider's duplicate, which depends on model timing. One `ttl-lru` run takes about 6 minutes of 14B and needs the owner's go-ahead.

The order that makes sense: the first $2.00 slice, then the live GitHub test, then the rest of item 5, item 7, item 8 and item 9. A failure at any step stays in the evidence. After a run, an owner record in `release/bar-records/` carries the result, as the [bar](RELEASE_BAR.md) describes.

## Known limits of this candidate

* No real model has driven `airlock protect`, Claude Code or Codex CLI through the boundary to a tool call. A first real run may find defects that a scripted reply cannot.
* A real Claude Code session may need more than the 1 GiB container limit.
* The Docker image store was emptied between sessions, so images were rebuilt. `release/acceptance-v2/config.json` can no longer be reproduced byte for byte, and its results stand as recorded.
* Acceptance v2 repeats were not independent samples: 8 of 10 repeat pairs had identical token counts, because the model is close to deterministic for a given prompt.
* Default prices in `agents.py` set the spend bound. They were checked on 2026-10-06 and must be rechecked before a release.
