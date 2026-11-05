# V4.4b credential-isolation audit

Starting head `5f880ce` (exact-head CI run 41929384433: all four jobs passed). Repaired source `cf3d14a`, source digest `a287d5dab6363aa57945bfe8db1bb603e8d7f227a4a1b431631509b0ca556735`, reproduced independently from Git objects. No paid inference, real GitHub consequence, merge, tag or release occurred.

## The boundary, as measured

Each row was established by an independent process: probe executables named `docker`/`git` first on `PATH` on the host, and a probe the real Codex 0.166.0 agent ran inside its container. Probes compare SHA-256 digests of a synthetic supervisor key and a synthetic grant signing key; no plaintext secret is printed or stored.

| Process | Before (`5f880ce`) | After (`cf3d14a`) |
|---|---|---|
| Supervisor (runner + broker, one process) | holds the key in `os.environ` for the whole run | holds it in a local variable; `os.environ` only during broker construction, then the broker's memory |
| Runner `git rev-parse` (identity) | **inherits API key + signing key** | allowlisted env, neither |
| Baseline `docker run` / `docker rm` client | **inherits API key + signing key** | allowlisted env, neither |
| Scoring `docker run` clients (visible/hidden tests) | **inherits API key + signing key** | allowlisted env, neither |
| Attack positive-control `docker run` | inherits (same code shape; not separately probed) | allowlisted env |
| Protected `Docker` client (bridge, agent, inspect) | allowlisted already: clean | unchanged, now via the shared allowlist |
| Contained agent, protected launch | **clean**: opaque marker only; no env or readable `/proc/*/environ`/`cmdline` token matches | clean |
| Contained agent, baseline launch | **clean**: `OPENAI_API_KEY` is the intended dummy `baseline-no-standing-credential` (preserved) | clean, dummy preserved |
| Run workspace, control files, agent log, receipts, console | no supervisor key bytes | none |

**Demonstrated exposure:** trusted host subprocesses only. There is no evidence that any container received the real key. Docker's `--env NAME=VALUE` form never forwards host values, and the in-container probe confirms this on both launch paths. The exposure was nonetheless real: Docker CLI plugins, credential helpers or anything else those clients spawned could read the key and the grant signing key.

## Repair (`cf3d14a`)

- `credential_preflight.supervisor_scope(name, value)`: sets the variable only for the duration of a `with` block, then restores the previous state. The runner wraps the existing broker-constructor hook in it. `Broker.__init__` already copies bound credentials into `self.credentials`, so authorised inference is unchanged: the broker still materialises `Bearer <key>` at the HTTPS edge, as a test verifies.
- The runner validates the key into a local variable and removes `OPENAI_API_KEY` from `os.environ` before any other work. Scripted runs use the fixed scripted value through the same path and never use an engineering-environment credential.
- `common.host_environment()`: an explicit allowlist (`HOME, PATH, TMPDIR, DOCKER_CONFIG, DOCKER_CONTEXT, DOCKER_HOST`), identical to what the protected `Docker` client already used and now shared with it. It is passed to the runner's `git` and Docker calls, the scoring containers and the attack control. This also excludes `ACTENON_SIGNING_KEY`, which the broker places in `os.environ` for Permit.

No new dependency. Provider-error sanitising, pre-flight, exact authority checks, replay ownership, budget controls and signed accounting are untouched.

## Verification

- Isolation regression (`test_supervisor_credential_isolation.py`): before, 5 failed / 3 passed (`before-isolation.txt`); after, **8 passed** (`after-isolation.txt`). The 3 that passed before are the clean protected Docker client and both in-container probes.
- Full Airlock suite with real Docker 29.9.2 and all three images: **2,048 passed, 0 failed, 0 skipped**.
- Scripted valid-response Codex workflow, baseline and protected: runner and agent exit 0, 3 visible + 4 hidden passes, 4/4 confirmed, 4,220 µUSD estimated, journals verify ANCHORED.
- Scripted malicious-hook controls: identical to before. Baseline: 2 agent canary deliveries. Protected: 0. Positive control delivers in both; hook files unchanged; journals verify ANCHORED.
- Real-Codex 401 leak check on this source: Codex saw status 401 and the fixed Airlock message only, with zero leak markers across the console and 24 run files. The signed observation reads `401` / `invalid_api_key`, and the outcome is AMBIGUOUS (`e2e-real-codex-401.json`).
- Lint and format (CI scope), wheel and sdist, clean wheel install, `doctor`, and wheel/source parity (31 files) all pass.

## Residual inheritance (not on the live runner path)

- `State.from_git` (`git show`, used only by `airlock diff --base`) and the v2 local-model harness helpers (`run_baseline`, `run_protected`, `airlock`, `run_identity`) still inherit the caller's environment. None is reachable from the Codex acceptance runner. The v2 `run_protected` subprocess legitimately needs its caller's credential.
- Within the supervisor process, the broker keeps the key in memory and puts the grant signing key in `os.environ` for Permit. That is the trusted process by design.
