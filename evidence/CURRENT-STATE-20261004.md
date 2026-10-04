# Airlock implementation state — 4 October 2026

Supersedes the LIMITS of `CURRENT-STATE-20261003.md`, which is kept as history.

## What changed

Airlock now has a general capability-provenance pipeline for cooperative Python agents. Nothing in
it is keyed to an agent or a repository.

- Scan names every power. Runtime effects are classified with Scan's own vocabulary
  (`classify_http`, the program's basename, and Scan's path normaliser).
- Adapters are registered by Scan power kind (`src/actenon_airlock/adapters.py`):
  - `http.*` and `github.*`, including `github.graphql` and dynamic `http.request`, are executed by
    the broker.
  - `process.exec`, `filesystem.write`, and `filesystem.delete` are released to the agent process
    after Permit decides and the Kernel verifies the proof.
  - `email.send` is intercepted and always denied.
- Every supported effect requires a signed grant and produces an Ed25519-signed, hash-chained
  receipt. `airlock receipts` verifies the log against `.airlock/public-key.json`.
- Unresolved, template, and unscanned calls are denied one call at a time. They no longer block
  launch. Launch is refused only for a Scan power kind with no adapter; none of the three agents
  has one.
- A denied HTTP call raises the client library's own connection error, which is also a
  `PermissionError`, so the agent's existing error handling runs. Airlock never kills the process
  for a denied call.
- Fixed a latent bug where every Permit decision after the first ALLOW in a session failed grant
  verification.
- The source guard covers the files that were scanned, so an agent that creates files in its tree
  keeps its session. New files carry no authority.
- `import ctypes` is allowed. Loading a named shared library and every symbol lookup are still
  refused.

Airlock is a cooperative Python broker, **not an OS jail**: native code and hostile same-user code
need OS isolation.

## Acceptance: three unmodified agents, full tree, pinned SHAs

Agents: pr-agent `4dd65356068d5dd3c5552f4f6696813d1fd10588`, gpt-engineer
`a90fcd543eedcc0ff2c34561bc0785d2ba83c47e`, agno `a4a7e319e9124a00c50f7815e4cea2bb3cae28e5`.

Each agent got its own venv with its own dependencies plus this Airlock checkout. For each one:
`airlock init --approve` signed only the resolved powers, then `airlock run --path <clone>` ran the
agent's real entry point. No GitHub, OpenAI, or Anthropic token was present. The only key was a
placeholder `OPENAI_API_KEY` on pr-agent's review run; the agent received a credential handle, and
that call was denied in any case. The commands are in `acceptance-20261004/run.sh`.

Discovery on the pinned Scan, from `acceptance-20261004/*-discovery.json`:

| Agent | Approved powers | Unresolved call sites (denied if reached) | Kinds without adapter |
|---|---|---|---|
| pr-agent | 7 (http 3, github.graphql 1, process 2, filesystem 1) | 83 | none |
| gpt-engineer | 7 (http 2, process 2, filesystem 3) | 20 | none |
| agno | 137 (http 104, filesystem 31, process 1, github 1) | 571 (plus 1 email.send denied by policy) | none |

On the evidence pack's checkout, every full-tree run exited 2 at launch.

### Results on pinned Scan a9de0ffe (`acceptance-20261004/pinned-scan/`)

| Run | Exit | What happened |
|---|---|---|
| `pr-agent -m pr_agent.cli --help` | 3 | Ran to completion. litellm's price-map fetch (a dependency) was denied; litellm fell back to its bundled copy. |
| `pr-agent --stdin review` | 3 | Reached tokenization. The tiktoken download was denied and pr-agent reported "Failed to process the command". A read of gcloud credentials outside the project was refused. |
| `gpt-engineer --sysinfo` | 1 | `subprocess.run([sys.executable, "-m", "pip", ...])` is unresolved and was denied before spawn. gpt-engineer does not catch the `PermissionError`. |
| `gpt-engineer --llm-via-clipboard` | 3 | Black's cache-directory write under `~` was denied and black handled it. Stopped at the tiktoken download. |
| `agno cookbook/91_tools/file_tools.py` | 0 | **All 14 Scan-named writes were ALLOWed and released with Kernel receipts.** The script ran to its model step and exited reporting "OPENAI_API_KEY not set". |

Receipts verified: pr-agent 5/5, gpt-engineer 6/6, agno 28/28. No receipt records a credential
release.

### Results with the coordinated Scan change (`acceptance-20261004/coordinated-scan/`)

The Scan change is in `docs/scan-pr/` (Scan commit `c94d1d0e`, based on a9de0ffe). It was installed
into each agent venv for this run.

| Run | Exit | What happened |
|---|---|---|
| `pr-agent --stdin review` | 3 | **`tiktoken` `o200k_base` download ALLOWed and executed by the broker.** The full review pipeline ran. All 12 model attempts through litellm, including fallback models, were denied as unresolved (Scan cannot resolve the model there). Writing `review.md`, whose path comes from argv, was denied. pr-agent's own error handling ended the run. |
| `gpt-engineer --llm-via-clipboard` | 3 | **`tiktoken` `cl100k_base` download ALLOWed.** Then the memory directory under `projects/example`, a path that comes from argv, was denied as unresolved, and gpt-engineer exits. |
| `agno file_tools.py` | 0 | Same as pinned: 14 ALLOWs and exit 0. |

Receipts verified: pr-agent 22/22, gpt-engineer 9/9, agno 28/28. No credential release.

## What still fails closed, by design

These are not per-agent gaps; each one is the general rule applied.

- **Paths, programs, and model names that come from argv, configuration, or runtime data.** Scan
  cannot name them, so Airlock denies each such call with a receipt. Examples: gpt-engineer's
  project directory, pr-agent's `--output` file and its litellm model selection, and
  `sys.executable -m pip`. Making these runnable requires Scan to name them statically. Adding a
  runtime allowlist would break "Scan vocabulary is law".
- **Effects inside dependencies with no agent callsite Scan names.** Examples: litellm's
  import-time price map, black's cache directory, tiktoken's cache directory under `/tmp`. The
  libraries tolerate each of these denials.
- **Reads outside the project and its import paths**, which keeps `~/.config/gcloud`, `~/.aws`, and
  similar files away from the agent.
- **Released programs.** Once `git` or another approved program runs, what it does is outside
  Airlock.

## Scan coordination

The agent's credentials cannot push to Actenon/actenon-scan (HTTP 403), so the Scan PR could not be
opened from this run. The patch, its description, and its validation are in `docs/scan-pr/`:
1348 Scan tests pass, with no new lint findings. Airlock works with both Scan versions: it prefers
Scan's new public `normalise_path` and falls back to the private name on 1.6.0. Once that PR merges,
bump the `actenon-scan` pin in `pyproject.toml` to the merge commit.

## Validation

- `local-tests-20261004.xml`: 85 passed on the pinned Scan. The same 85 pass with the coordinated
  Scan installed.
- CI: Integration on Python 3.11 and 3.12, plus Package and lint, on PR #3.
