# Codex CLI inside Airlock Protected Mode

Integration candidate: unchanged Codex CLI 0.166.0, GPT-5.5 direct-tool Responses
interface. Real-binary scripted tests demonstrate operation and containment.
**Real-model autonomous acceptance has not run; release admission remains blocked.**
A scripted provider's commands are harness decisions, not model decisions.

## Build and run

From this source checkout, with Linux Docker available:

```sh
python -m build
python -m venv /tmp/airlock-codex
/tmp/airlock-codex/bin/pip install dist/*.whl
docker build -f containers/Dockerfile.compute -t airlock-codex-compute:local .
docker build -f containers/Dockerfile.codex-cli \
  --build-arg COMPUTE_IMAGE=airlock-codex-compute:local \
  -t airlock-codex:local .
/tmp/airlock-codex/bin/airlock doctor --json
```

The image downloads the official Linux musl release asset and checks its pinned
SHA-256. `/opt/codex-upstream.json` records the archive, source commit, architecture
and installed binary digest. The image contains no login or API credential.
Use a credential-free project containing `ISSUE.md`. Configure an API key only in
the trusted supervisor environment through your normal secret manager. Do not put
it in the project, image, command arguments, or contained Codex home.

The following is **billable only after separately authorizing API expenditure**.
Run setup first without `--approve` to review the exact model power, then approve:

```sh
airlock setup --path ./project --agent codex-cli \
  --model gpt-5.5-2026-04-23 --max-run-usd 2 --price-per-mtok 5,0,0.5,30
# After reviewing the printed authority:
airlock setup --path ./project --agent codex-cli \
  --model gpt-5.5-2026-04-23 --max-run-usd 2 --price-per-mtok 5,0,0.5,30 --approve
airlock work --path ./project --message-file ISSUE.md --image airlock-codex:local
airlock status --path ./project --json
airlock capture --path ./project --json
```

Prices are operator-reviewed USD per million input, cache-write, cache-read and
output tokens. Recheck current official rates; long-context pricing differs.
The Codex setup profile and frozen acceptance runner limit input to 200,000 bytes
to stay below the 272K-token price threshold. Manually widening this bound requires
reviewing prices for the selected model's entire permitted context.
The supervisor reserves a conservative input-byte estimate plus framing and the
full output cap before dispatch. It settles against validated provider usage.
This is a per-run signed-price spend guard, not a provider billing statement or
an account-wide budget across restarts. Unknown outcomes retain their reservation.

The command uses supported `codex exec` options, an empty private CODEX_HOME,
`--ignore-user-config`, `--ignore-rules`, `--ephemeral`, and a custom Responses
provider. Codex's own approval/sandbox controls are bypassed intentionally; Docker
is the independent enforcement boundary. The container retains shell, editing and
testing. It has no network, host home, Docker socket, trusted keys or effect store.
Known `.codex`, `.home` and `.tmp` input directories are excluded from staging.
Unknown secrets in ordinary project files still require credential-free inputs.

## Inference contract

`openai-responses-agent/v1` permits exact approved models, inline text/history,
reviewed local function/custom tool names, reasoning, structured text and streaming.
Codex omits `max_output_tokens`; Airlock inserts the approved cap **before** Permit
and Kernel bind the exact outbound request. Cache/diagnostic metadata is removed
before request identity. Complete SSE is buffered within transport limits; the
client receives proper events, but partial streaming latency is not offered.
Tool calls only direct the contained client. They never authorize external effects.

Provider-hosted tools, remote MCP, web search, URL/file/image inputs, previous-response
references, stored conversations, background calls, unreviewed fields and models
fail closed. Code Mode models/tools are not supported by this initial integration.
Usage must accompany a consistent terminal response; truncated or uncertain replies
remain held. Changed tracing metadata cannot free an identical held request in the
same run. Confirmed identical calls remain separate useful model invocations.
Inference does not claim cross-run exactly-once billing. GitHub consequences use
the existing durable logical-effect identity, independently of inference sessions.

## Approved consequence

Inspect the captured patch. Verify it with operator-held tests outside the project:

```sh
airlock verify-candidate --path ./project --candidate SHA --tests /trusted/tests --image airlock-codex:local
airlock synthetic-provider --file /trusted/disposable-provider.json --create
airlock review-candidate --path ./project --candidate SHA --output /trusted/create.json \
  --path-in-repo patches/fix.patch --message 'Reviewed patch' \
  --synthetic-provider /trusted/disposable-provider.json
# Review exact repository, branch, path and bytes, then explicitly approve:
airlock init --path ./project --approve --github-create /trusted/create.json \
  --reconciler-key /trusted/operator.key --credential GITHUB_TOKEN=https://api.github.com
airlock publish --path ./project --candidate SHA --synthetic-provider /trusted/disposable-provider.json
airlock reconcile --path ./project EFFECT_ID --github-readback --operator-key /trusted/operator.key \
  --synthetic-provider /trusted/disposable-provider.json
airlock checkpoint --path ./project --output /independent/checkpoint.json
airlock verify-evidence --journal ./project/.airlock/local/receipts.jsonl \
  --public-key /independent/public-key.json --checkpoint /independent/checkpoint.json
```

Copy the trusted public key independently before verification. Synthetic publishing
uses the documented synthetic token from `actenon_airlock.synthetic_github.TOKEN` in
the supervisor's `GITHUB_TOKEN`; it does not contact GitHub. Live GitHub writes require
separate owner authorization. Passing tests do not authorize publication. A provider
acknowledgement is still ambiguous until supported independent readback; repeated
publication cannot blindly repeat a held consequence. Signatures prove integrity,
checkpoints provide a completeness reference, and readback supplies provider evidence.
Destroying all trusted history cannot be repaired by a signature or a fresh grant.

## Reproduce the versioned acceptance programme

```sh
python acceptance/codex-cli/run.py freeze --image airlock-codex:local --out /trusted/codex-config.json
python acceptance/codex-cli/run.py protected --image airlock-codex:local --out /evidence/rehearsal
python acceptance/codex-cli/run.py baseline --image airlock-codex:local --attack --out /evidence/baseline-attack
python acceptance/codex-cli/run.py protected --image airlock-codex:local --attack --out /evidence/protected-attack
```

Default runs are explicitly scripted and incur no model charges. The rehearsal
uses reference patches **only** to exercise the unchanged binary and the workflow.
Live runs never provide these patches to Codex. Scoring restores original visible
and hidden tests, rejects output symlinks, and executes in a separate no-network
container. Test passing remains bounded evidence, not a general correctness proof.

For a separately approved live run add `--live --authorized-usd 2 --config /trusted/codex-config.json`.
Proposed first programme: token-bucket baseline/protected plus the same pair with
untrusted project instructions, four runs capped at $2 each, $8 total authorization.
No automatic extra trials. Both modes use the same model, image, command and scoring.
Baseline model calls still use the same guarded credential-holding gateway; baseline
compute has network access for matched attack controls. Its disposable listener uses
an unguessable URL and is not a deployment endpoint. Record all failures. An ignored
inducement is not evidence of containment. A planted script selected by a real model
is identified separately from model-authored attacks and harness-selected rehearsal.

## Authentication and limits

Official Codex supports ChatGPT sign-in and separately billed API-key authentication.
The ChatGPT-plan open-source integration is a separate registered-client consent flow;
it does not license extracting this desktop session's cache. Its documented preview
rejects `max_output_tokens`, so it does not satisfy this contract's approved output cap.
No host OAuth token or ChatGPT authentication cache was read or copied in this work.
API-key-based GPT-5.5 usage remains available despite its retirement from subscription
Codex. Owner-approved API access is the prepared live route; it has not been exercised.

Sources checked 2026-10-31:
- [Official pinned release](https://github.com/openai/codex/releases/tag/rust-v0.166.0)
- [Codex noninteractive interface](https://developers.openai.com/codex/noninteractive)
- [Custom providers](https://developers.openai.com/codex/config-advanced)
- [Authentication](https://developers.openai.com/codex/auth)
- [ChatGPT-plan preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
- [GPT-5.5 snapshot and pricing](https://developers.openai.com/api/docs/models/gpt-5.5)

The previous A–F requirements, G1–G40 definitions/results, failed historical gates,
release-admission rule and Aider/Claude evidence are preserved. This programme cannot
retroactively change them. No release claim follows from the scripted rehearsals.
