# Release candidate checkpoint

Branch `feat/airlock-release-candidate`, draft [PR #20](https://github.com/Actenon/actenon-airlock/pull/20) against `feat/airlock-milestone-1`. Status: **NOT READY**. No designation is awarded. Nothing is merged, tagged, published or deployed, and no paid inference or live GitHub write has happened.

Start with [what a release still needs](RELEASE_BAR.proposed.md).

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

## Open

Everything engineering can finish alone is done. These remain, and each needs the owner:

1. Accept [the proposed bar](RELEASE_BAR.proposed.md), or commit G1-G40.
2. Authorize the first real-model slice, capped at $2.00, and set an API key. See [LIVE_RUN.md](acceptance-claude-code/LIVE_RUN.md).
3. Run the [live GitHub test](acceptance-v2/LIVE_TEST.md), or authorize it.
4. Show real Aider exits 0 with a real model. The repeated-inference fix has a real-boundary test with an SDK client, and a failing reproduction on the scored wheel. The confirming run was stopped because 14B made the Mac unusable. A scripted model could not reproduce Aider's duplicate, because it depends on model timing. One `ttl-lru` run takes about 6 minutes of 14B, and it needs the owner's go-ahead.
5. Name three original repositories for the ten-case gate.
6. Merge the Kernel and Permit candidates, and publish the packages and images.
7. Find two independent operators.

## Known limits of this candidate

* No real model has driven `airlock protect`, Claude Code or Codex CLI through the boundary to a tool call. A first real run may find defects that a scripted reply cannot.
* A real Claude Code session may need more than the 1 GiB container limit.
* The Docker image store was emptied between sessions, so images were rebuilt. `release/acceptance-v2/config.json` can no longer be reproduced byte for byte, and its results stand as recorded.
* Acceptance v2 repeats were not independent samples: 8 of 10 repeat pairs had identical token counts, because the model is close to deterministic for a given prompt.
* Default prices in `agents.py` set the spend bound. They were checked on 2026-10-06 and must be rechecked before a release.
