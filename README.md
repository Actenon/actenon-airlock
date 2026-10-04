# Actenon Airlock

**See what new powers your AI agent gained before it uses them.**

Airlock discovers authority from Python source with Actenon Scan, shows new and removed powers,
and brokers supported HTTP calls through Actenon Permit and Kernel. A new or unresolved power
cannot execute through that broker until its resolved authority is explicitly approved.

This is an installable development product, version 0.1.0.dev0. Its dependencies are pinned to the
merged, unified ecosystem line. These are staging source pins; public registry dependencies are still
a release gate. No Airlock package, tag, or release has been published.

## Install

Python 3.11+ on Linux or macOS, with Git installed:

~~~sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install "git+https://github.com/Actenon/actenon-airlock.git@main"
airlock doctor
~~~

One Airlock installation includes Scan, Permit, Kernel, and Protocol at the exact commits in
[dependency-pins.json](evidence/dependency-pins.json). Install your agent's own requirements
in the same environment. For repeatable deployment, replace main with a reviewed Airlock commit.

## Quickstart

In your agent's project:

~~~sh
airlock init --command "main.py"
~~~

Review the displayed action, resource, and transport. Then explicitly activate the resolved powers:

~~~sh
airlock init --approve --command "main.py"
airlock run
~~~

You can also select the script directly: airlock run -- main.py arg1.
Python modules are supported with airlock init --approve --command "-m myagent".
If exactly one of main.py, agent.py, or run.py exists, Airlock selects it automatically.
Init without --approve writes a proposal; it does not grant authority.

Change a POST URL or add a DELETE call, then:

~~~sh
airlock diff
airlock diff --json
airlock check
airlock run
~~~

~~~text
AIRLOCK AUTHORITY DIFF

+ http.delete @ api.example.com/sessions
  Transport: https://api.example.com/sessions

Runtime: BLOCKED UNTIL APPROVED
~~~

Existing approved powers can continue. New powers are denied by Permit. Removed powers are
automatically removed from the runtime grant. Re-run init --approve after reviewing the change
to activate the new resolved powers. Templates and unknown targets stay blocked after approval.

For a demonstration without any external account, run examples/server.py directly in one terminal.
In another terminal, change into examples/agent and run init --approve followed by run.
Then change the POST to DELETE in main.py: diff shows the new power and run denies it.

## Credentials and receipts

The parent broker retains credentials. The agent receives opaque handles for GITHUB_TOKEN,
GH_TOKEN, OPENAI_API_KEY, and ANTHROPIC_API_KEY, bound to their standard HTTPS API origins.
Only a verified, authorized request can materialize a handle in an authorization/API-key header.
Unknown environment variables are not inherited; nonsecret configuration inputs observed by
Scan are forwarded. The broker ignores proxy environment variables.
SDK credential-profile discovery is directed to a new, empty per-run directory.

For a custom credential, bind it during approval:

~~~sh
airlock init --approve --command "main.py" --credential SERVICE_TOKEN=https://api.example.com
~~~

Bindings are part of the signed approval. Pass credentials in the parent environment, not in
source, CLI arguments, URLs, or request bodies. Files such as .env, private keys, and Airlock's
local state are unavailable to the child. Nonsecret .env inputs used by discovery are forwarded
as environment variables, so use os.environ rather than reopening .env from the agent.

The terminal prints ALLOW/DENY receipts. Durable evidence is at
.airlock/local/receipts.jsonl, including action, exact target, source and manifest digests,
Scan location, Permit decision/grant, proof identifier, Kernel receipt or refusal, timestamp,
and credential/execution flags. Authorization is recorded before the effect; execution gets a
linked completion record. A transport failure after dispatch records an unknown execution result.
Request and response bodies, raw headers, and credential values are not recorded.
If the agent handles an error itself, Airlock still exits nonzero for a broker denial (3) or
an uncertain/failed dispatch (4). Discovery and approval-check failures exit 2.

Commit .airlock/approved.json and .airlock/public-key.json for CI review.
Keep .airlock/local/ private; it contains the approval signing key and local runtime evidence.
A fresh checkout cannot reapprove or run until its trusted local key is provisioned.

## CI and pull requests

~~~sh
airlock check --base origin/main --github --output authority-diff.json
~~~

The baseline approval and public key come from the **trusted base revision**, so a PR cannot approve
itself by editing its manifest or public key. No reviewed Python code is executed during discovery.
Missing/invalid baselines, parse errors, authority expansions, and unresolved authority fail the check.
GitHub job summaries show the human-readable diff; JSON is suitable for other CI systems.
See [the reusable action](action.yml) and [workflow example](docs/github-action.md).

## Supported boundary

- Python requests (including PyGithub), httpx sync/async, and urllib.request.
- Generic HTTP authority binds the scheme, host, port, exact path, and query.
- GitHub authority uses Scan's action and repository vocabulary and an HTTPS API origin.
- Requests and responses are buffered, limited to 4 MiB. Redirects are returned without being followed.
- Runtime HTTP must trace to resolved Scan evidence in the project. Unresolved calls cannot inherit
  the authority of a resolved call to the same URL.
- Source lines and columns distinguish callsites. Ambiguous async expressions or source sites
  shared with unresolved evidence remain blocked.
- Adapters are registered by Scan power kind: HTTP and GitHub (including GraphQL and dynamic
  methods) are executed by the broker, while process and filesystem effects are released to the
  agent after Permit and the Kernel verify them. `email.send` is intercepted and always denied.
- Unresolved, template, and unscanned calls are denied one call at a time with a signed receipt;
  they no longer block launch. Launch is refused only for a Scan power kind with no adapter.
- Receipts are Ed25519-signed and hash-chained; `airlock receipts` verifies them.
- Raw sockets, forks, native library loading, aiohttp, and reads outside the project fail closed.

Airlock's Python adapter and audit hooks protect cooperative Python agents from unintended powers.
They are **not an OS sandbox for hostile code**, native extensions, or an attacker controlling the
same user account, interpreter, source, or local signing key. Use OS/container isolation for that
threat model. Airlock does not claim complete discovery of arbitrary Python, other languages, or
unadapted frameworks. See [the enforcement design](docs/enforcement.md) and [security policy](SECURITY.md).

## Development

~~~sh
python -m pip install -e ".[test]"
python -m pytest -q
ruff check src tests
ruff format --check src tests
python -m build
~~~

The tests use real pinned Scan, Permit, and Kernel components, real HTTP clients and loopback servers.
They exercise target changes, approvals, empty/unresolved authority, credential release, revocation,
proof mutation/replay, JSON/CI output, and attempted runtime bypasses.
