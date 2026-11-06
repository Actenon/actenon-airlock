# Using Airlock on a real project

`airlock protect` works the same way on any project: review, work, check, receipt, and a patch
you choose whether to take. This page covers what differs between Python, Go and TypeScript
projects, and what you should know about credentials and tests before you rely on it.

## The command

~~~sh
cd my-project
export ANTHROPIC_API_KEY=...            # or OPENAI_API_KEY for Codex CLI
airlock protect --tests ../my-project-tests "Fix the bug described in issue 42"
~~~

Useful options:

| Option | What it does |
|---|---|
| `--tests DIR` | Check the agent's change with tests from `DIR`, kept outside the project. |
| `--max-run-usd N` | The spend limit per run (default 2). Changing it asks you to approve again. |
| `--agent claude-code` / `--agent codex-cli` | Choose the agent. Without it, Airlock picks the one whose key is set. |
| `--image NAME` | Run the agent and the checks in your own image (for toolchains and dependencies). |
| `--accept-skips` | Count skipped tests as acceptable. Recorded in the receipt. |
| `--allow-config-change` | Accept a change by the agent to the files that define your checks. Recorded. |
| `--approve` | Approve without the question, for scripts. You still see what was approved. |

## Why your tests live outside the project

The agent can edit anything in its copy, including tests. If it could change the tests that
judge it, a pass would mean little. With `--tests DIR`, Airlock copies the agent's change and
your trusted tests into a fresh sealed container, with your original project's test settings
(for example the `[tool.pytest.ini_options]` in your own `pyproject.toml`, not the agent's
copy). If the agent changed those settings files anyway, the result is INCONCLUSIVE unless you
pass `--allow-config-change`.

A practical layout: keep the regression test for the task in a folder next to the project,
such as `../my-project-tests/test_issue_42.py`, and pass that folder.

## Python

Airlock runs `python3 -m pytest -q -p no:cacheprovider` with your project's pytest settings,
`src/` and the project root on `PYTHONPATH`. The agent images include Python and pytest. If
your tests import other packages, build them into an image (below).

## Go

Airlock runs `go vet ./...` and `go test -json ./...`, offline (`GOPROXY=off`,
`GOTOOLCHAIN=local`). The agent images do not include Go, so pass an image that does. Without
one, `airlock protect --tests` stops before the agent runs, says nothing was spent, and prints
the build command.

## TypeScript and JavaScript

From your own `package.json`: `tsc --noEmit -p tsconfig.json` when you depend on TypeScript and
have a `tsconfig.json`, and `vitest run` when you depend on vitest. Otherwise `npm test`. The
agent images do not include Node or your dependencies, so pass an image that has them.

## Your project's toolchain

The sealed container has no network, so the toolchain and every dependency your checks need
must already be in the image. Airlock ships three recipes in
[examples/toolchains](../examples/toolchains). Each starts from the agent's image and adds:

| Recipe | Adds | Your project needs |
|---|---|---|
| `Dockerfile.go` | Go, plus your modules from `go.mod` and `go.sum` | `go.mod` |
| `Dockerfile.node` | Node, npm, and `npm ci` of your lockfile, install scripts off | `package.json`, `package-lock.json` |
| `Dockerfile.python` | Your test requirements, each checked against its hash | `requirements-test.txt` with hashes |

Build from your project folder. When `airlock protect` refuses because a tool is missing, it
prints this command with the recipe from the exact commit you installed:

~~~sh
curl -fsSL https://raw.githubusercontent.com/Actenon/actenon-airlock/<commit>/examples/toolchains/Dockerfile.go \
  | docker build -t my-project-airlock:go -f - .
airlock protect --image my-project-airlock:go --tests ../my-project-tests "Fix the bug"
~~~

For Codex CLI, add `--build-arg AGENT_IMAGE=actenon-airlock-codex-cli:v1`.

The build itself has network access and reads your dependency files, so build from a version of
the project you trust. The dependencies end up outside the agent's workspace, so the agent can
use them but not change them. CI builds the Go and Node recipes and runs the full set of check
outcomes against them.

## Credentials

- Your model key stays in Airlock's supervisor on your machine. The agent gets a stand-in that
  only works through Airlock, for the approved model, within the signed bounds.
- Nothing else is passed in: no `GITHUB_TOKEN`, no SSH keys, no cloud credentials, no home
  folder.
- `.env` files and known credential folders (`.ssh`, `.aws`, `.config` and others) are not
  copied into the agent's workspace.
- A secret written into ordinary source code is copied, and the agent can send it to the model
  you allowed. Keep secrets out of source.

## What you get back

The receipt reports only what Airlock observed: files changed, checks run and their outcome,
calls refused, the estimated cost from the provider's reported usage, anything uncertain, and
where the evidence is. The agent's own summary is shown separately and labelled as its claim.

Nothing leaves the sealed copy. `airlock protect` never pushes, publishes or writes outside it.
To publish a reviewed change to GitHub as one exact file creation, confirmed by reading it
back, use the [golden path](golden-path.md#8-review-the-proposed-consequence).

## Limits

- One agent run is bounded by the spend limit and by the agent's own turn limit; Claude Code
  stops after 40 turns.
- Airlock limits what the agent can do, not whether its change is right. Read the patch.
- The workspace has no disk quota in this preview.
- Unsupported: projects whose checks need network access, services (databases, browsers) or
  hardware.
