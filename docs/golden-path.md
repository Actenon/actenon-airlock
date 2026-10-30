# Golden path: an existing coding agent, one reviewed consequence

This walks the supported journey with the commands this candidate ships. Discovery
proposes, and only a signature made on the trusted host approves. A command never
reports success for something only proposed, attempted or ambiguous.

To see the whole journey run itself, with its four results computed from independent
artifacts, run the [flagship demo](#see-it-work):

```bash
python acceptance/v2/flagship.py --model qwen2.5-coder:14b --out flagship-run
```

## Before you start

* Linux with a Docker engine, or Docker Desktop on macOS, which runs the same
  container boundary inside its Linux VM. Windows is not supported.
* Python 3.11 or 3.12.
* A model endpoint the supervisor can reach. A local Ollama server is the tested
  route. Ollama listens on port 11434 by default, and the examples use 11435 because
  the acceptance programme runs a private instance. The agent never sees a model
  credential.

## 1. Install

```bash
python -m pip install "git+https://github.com/Actenon/actenon-airlock.git@feat/airlock-north-star"
```

Build the images from a checkout of the same commit:

```bash
docker build -f containers/Dockerfile.compute -t actenon-airlock-compute:dev .
```

```bash
docker build -f acceptance/v2/Dockerfile -t actenon-airlock-aider:v2 acceptance/v2
```

## 2. Check the boundary

```bash
airlock doctor
```

If Protected Mode cannot be established, `airlock work` and `airlock run --protected`
refuse. There is no fallback to Local Mode.

## 3. Configure your agent and model

```bash
airlock setup --agent aider --model qwen2.5-coder:14b \
  --model-endpoint http://127.0.0.1:11435/v1/chat/completions \
  --reconciler-key ~/.config/airlock/operator.key
```

Aider is the one validated agent. Any other name is refused; `airlock run --protected`
applies the same boundary to other commands, without a compatibility claim.

## 4. Discover what the agent could do

`setup` scans the project and prints the authority difference. It grants nothing, and
`airlock diff` shows the same difference at any time. The file `airlock_agent.py` is a
reviewable declaration of the powers an agent installed in an image needs. It is never
executed.

## 5. Review and approve

Read the difference. To approve inference and nothing else, repeat the command with
`--approve`:

```bash
airlock setup --agent aider --model qwen2.5-coder:14b \
  --model-endpoint http://127.0.0.1:11435/v1/chat/completions \
  --reconciler-key ~/.config/airlock/operator.key --approve
```

The approval is an Ed25519 signature over the exact reviewed authority. It carries no
provider authority.

## 6. Run the agent in Protected Mode

```bash
airlock work --message-file ISSUE.md --test-command "python -m pytest -q"
```

The agent works on a copy with no network, a read-only root, all capabilities dropped,
and CPU, memory and process limits. Inference crosses the supervisor. Your project is
not modified.

## 7. See the output and what was blocked

```bash
airlock capture
```

```bash
airlock status
```

`capture` records the exact change as untrusted data, without executing it. Links,
special files and binary changes refuse the capture. `status` lists refusals and keeps
what happened apart from what is known about the outside world.

Run your own tests against the candidate, held outside the project so the agent could
not have changed them:

```bash
airlock verify-candidate --candidate <sha256> --tests ../trusted-tests
```

`TESTS_PASSED` means those tests passed with the candidate imported. It is not a safety
finding, and it approves nothing.

## 8. Review the proposed consequence

```bash
airlock review-candidate --candidate <sha256> --output reviewed-create.json \
  --path-in-repo patches/fix.patch --message "Publish the reviewed fix" \
  --repo-id <id> --repo-node-id <node-id> --owner <owner> --repo <repo> \
  --branch <branch> --parent <commit>
```

The profile names one repository, branch, path, message, parent commit and the SHA-256
of the exact bytes. Nothing is authorized yet.

## 9. Approve it

```bash
airlock init --approve --github-create reviewed-create.json \
  --reconciler-key ~/.config/airlock/operator.key \
  --credential GITHUB_TOKEN=https://api.github.com
```

Set `GITHUB_TOKEN` in the supervisor's environment only, with a token scoped to a
disposable repository. It never enters the agent's container.

```bash
airlock publish --candidate <sha256>
```

Exactly one create-only write is dispatched. A 201 is still held as `AMBIGUOUS`,
because a provider's reply is a claim. A lost reply is held the same way, and a retry
in any session, process or grant is refused without reaching the provider.

## 10. Verify the outcome independently

```bash
airlock reconcile effect_<id> --github-readback --operator-key ~/.config/airlock/operator.key
```

```bash
airlock checkpoint --output ../independent/checkpoint.json
```

```bash
airlock verify-evidence --journal .airlock/local/receipts.jsonl \
  --public-key ../independent/public-key.json --checkpoint ../independent/checkpoint.json
```

Readback never repeats the write. Offline verification answers three questions
separately: is the history intact, is it complete against an independently held
checkpoint, and what was independently observed at the provider.

## If something goes wrong

```bash
airlock stop --reason "why you stopped it"
```

This kills a running agent and refuses every dispatch and new run. `reconcile` still
works, and `airlock resume --reason "..."` clears the stop. Neither changes a held
effect. See [operations](operations.md).

## See it work

`acceptance/v2/flagship.py` runs this journey against a synthetic provider and a sink
on your own machine, so no account or network is involved. A repository planted with
malicious test code gives the attack a real path: the real agent runs it. The demo
writes `transcript.txt` and `summary.json` and exits non-zero unless all four results
hold:

* **Result A:** the agent does useful work under Protected Mode.
* **Result B:** the planted code and fixed abuse attempts do not exceed its authority.
* **Result C:** the reviewed consequence lands exactly once and is independently confirmed.
* **Result D:** a lost reply stays ambiguous, retries do not redispatch, and tampering is caught.

## What is verified, and where it stops

| Step | Evidence | Limit |
|---|---|---|
| Install from a built wheel in a fresh venv | CI `Package and lint` on PR #16 | Git-pinned dependencies; nothing is on PyPI |
| Protected boundary, 13 bypass attempts | CI `Protected container acceptance` (amd64); local Docker Desktop on Apple Silicon, 18/18 | Docker shares the host kernel; not microVM isolation |
| Exact GitHub create, refusals, `201_AMBIGUOUS`, readback | `tests/test_github_container.py` against a synthetic Contents API | Scripted agent and synthetic provider; no live GitHub mutation is authorized |
| Durable effect ownership across fresh grants and runs | `tests/test_github_container.py`, `tests/test_http_effects.py` | Single host |
| A real, unmodified agent doing useful work (steps 2–3) | **None passing.** Every frozen gpt-engineer run has failed; see [frozen acceptance history](evidence/frozen-acceptance-history/README.md) | Blocks CANDIDATE READY |
