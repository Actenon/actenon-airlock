# Golden path: an existing coding agent, one reviewed GitHub file

This walks the supported first workflow end to end with the commands this
candidate ships. Each step names the evidence that it works and where that
evidence stops. Nothing here grants authority automatically: discovery
proposes, and only a signature made on the trusted host approves.

The integration candidate is `integration/candidate-2026-10-29` (draft PR #16),
pinned to the Protocol, Kernel, Scan and Permit PR heads in
`release/candidate-manifest.json`. Status: **NOT READY** (see `release/README.md`).

## Before you start

* Linux with a Docker engine. Docker Desktop on macOS runs the same container
  boundary inside its Linux VM; the CI evidence is from Ubuntu, and the local
  evidence below is from Docker Desktop on Apple Silicon.
* Python 3.11 or 3.12.
* A model endpoint the supervisor can reach. A local Ollama server is the
  tested route; the agent never sees a model credential.

```sh
python -m pip install "git+https://github.com/Actenon/actenon-airlock.git@integration/candidate-2026-10-29"
docker build -f containers/Dockerfile.compute -t actenon-airlock-compute:dev .
airlock doctor
```

`airlock doctor` reports whether Protected Mode can be established. If it
cannot, `airlock run --protected` refuses instead of falling back to Local Mode.

## 1. Discover and review authority

```sh
airlock init --command main.py          # proposes; grants nothing
airlock diff                            # what is new, unresolved or unsupported
```

## 2. Approve model inference only

```sh
airlock init --approve --command main.py \
  --model qwen2.5-coder:14b --model-endpoint http://127.0.0.1:11434/v1/chat/completions \
  --model-max-tokens 1536 --model-read-timeout 600
```

The approval is an Ed25519 signature over the exact reviewed authority. The
model grant carries no GitHub authority.

## 3. Run the agent in Protected Mode

```sh
airlock run --protected --image actenon-airlock-compute:dev -- python3 main.py
```

The agent runs in a copied workspace with no network, a read-only root, all
capabilities dropped, and CPU, memory and process limits. Inference is
brokered by the supervisor. Unapproved requests are refused and recorded. The
run prints the workspace path; its contents are **untrusted output** and are
never executed on the host automatically.

## 4. Review the exact artifact

Inspect the change, compute its SHA-256, and write `reviewed-create.json` with
the disposable repository's IDs, branch, path, message, `content_sha256` and
the expected parent commit (schema in [github-consequence.md](github-consequence.md)).

```sh
airlock init --github-create reviewed-create.json --reconciler-key ~/.config/airlock/operator.key
airlock init --approve --github-create reviewed-create.json --reconciler-key ~/.config/airlock/operator.key
```

Passing tests are not approval. The experimental container test runner in
Airlock PR #15 can report `TESTS_PASSED` for a candidate, but it is outside this
candidate and never signs anything.

## 5. Publish exactly that file

```sh
airlock run --protected -- python3 publish.py
```

Only a PUT whose body is exactly `message`, base64 `content` and `branch` for
the reviewed path, branch and repository is dispatched, once. Anything else
fails closed. A response or timeout after dispatch leaves the effect
`AMBIGUOUS`; a 201 alone is never `COMMITTED`.

## 6. Settle with a read-only observation

```sh
airlock reconcile effect_<id> --github-readback --operator-key ~/.config/airlock/operator.key
airlock receipts --json
```

Readback never repeats the mutation. An unrelated object at the path does not
settle the effect.

## What is verified, and where it stops

| Step | Evidence | Limit |
|---|---|---|
| Install from a built wheel in a fresh venv | CI `Package and lint` on PR #16 | Git-pinned dependencies; nothing is on PyPI |
| Protected boundary, 13 bypass attempts | CI `Protected container acceptance` (amd64); local Docker Desktop on Apple Silicon, 18/18 | Docker shares the host kernel; not microVM isolation |
| Exact GitHub create, refusals, `201_AMBIGUOUS`, readback | `tests/test_github_container.py` against a synthetic Contents API | Scripted agent and synthetic provider; no live GitHub mutation is authorized |
| Durable effect ownership across fresh grants and runs | `tests/test_github_container.py`, `tests/test_http_effects.py` | Single host |
| A real, unmodified agent doing useful work (steps 2–3) | **None passing.** Every frozen gpt-engineer run has failed; see [frozen acceptance history](evidence/frozen-acceptance-history/README.md) | Blocks CANDIDATE READY |
