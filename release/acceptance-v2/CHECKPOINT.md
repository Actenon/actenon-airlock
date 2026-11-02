# Acceptance v2 checkpoint

Branch `feat/airlock-north-star`, draft [PR #18](https://github.com/Actenon/actenon-airlock/pull/18) against `feat/airlock-milestone-1`. Status: **NOT READY**. Start with the [verdict](VERDICT.md).

Scored code: `67837913f9379772f93ed9e34d244f187e1dde3f`. Frozen config: `release/acceptance-v2/config.json`, sha256 `e96b59e1b48c792bad12ef04deccbae2ccefc63ba862527d9ea30f85b06fe553`.

## Resume

```bash
git checkout feat/airlock-north-star
```

```bash
uv venv -p 3.12 .venv && uv pip install -e ".[test]"
```

```bash
docker build -f containers/Dockerfile.compute -t actenon-airlock-compute:dev .
```

```bash
AIRLOCK_TEST_PROTECTED_IMAGE=actenon-airlock-compute:dev .venv/bin/python -m pytest -q
```

To rerun the acceptance programme, follow [acceptance/v2/README.md](../../acceptance/v2/README.md). Local requirements: a private Ollama on port 11435 with `OLLAMA_CONTEXT_LENGTH=8192`. A larger context swaps a 16 GB machine.

## Done

* PR #17 integrated with its history intact.
* Guided workflow, synthetic provider, emergency stop, and approval and credential controls.
* Acceptance v2: corpus, harness, adversarial evidence, flagship, frozen config, mechanical scorer, and 28 scored runs.
* Cross-language conformance and the 32-case parity corpus reproduced.
* Docker-only tests made mandatory in the gate.
* Operations, golden path, acceptance matrix, and the live test procedure.

## Open, in order

1. **Owner decision:** allow an identical inference request within one run, inside the 128-call budget. Today it is refused, an existing test requires that, and it caused exit 3 in 4 of 10 protected utility runs, all on `ttl-lru` and `invoice-totals`.
2. **Owner decision:** how to resolve U1: keep the threshold and change the model or corpus, or accept the spec with a different threshold. Any change needs a new freeze and a full rerun, and this programme's results stand.
3. **Owner action:** run [the live test](LIVE_TEST.md) on a disposable repository.
4. **Owner action:** commit the verbatim G1-G40 text, so the gate can define G1-G27, G39 and G40.
5. **Owner decision:** whether to accept `release/acceptance-v2/spec.json`.
6. Have an independent operator reproduce this on a fresh machine.

## Rules that still apply

No merges into protected branches, tags, publication, deployment, live provider mutations, paid inference or paid GPU without owner authorization. Never alter a test to get a green result. Never substitute v2 results into G1-G40.
