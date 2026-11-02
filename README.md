# Actenon Airlock

**Let AI agents work. Never surrender control.**

A coding agent needs real access to be useful, and that access is the risk. One poisoned
README, dependency or issue can turn it against your keys, your code and your GitHub. So you
either watch every step or run it wide open.

Airlock is the third option. Your unchanged agent runs in a sealed container with a copy of
your project. It can read, edit and run code as usual. It has no network, no credentials and
no route to your home directory, and nothing it produces reaches your project until you
read it and take it.

## See it in a minute

No key, no model and no cost. You need Python 3.11+, Git and a running Docker.

~~~sh
python3 -m pip install "git+https://github.com/Actenon/actenon-airlock.git@feat/airlock-release-candidate"
airlock demo
~~~

A script does a small job, then acts like a hijacked agent. It runs once in an ordinary
container and once in Protected Mode, and the result comes from what reached an independent
sink:

~~~text
                              Ordinary container    Protected Mode
Fix the bug                   done                  done, as a patch to review
Steal the GitHub token        LEAKED                nothing got out
Steal the project's .env      LEAKED                nothing got out
Steal the SSH private key     LEAKED                nothing got out
Send data straight out        LEAKED                nothing got out
Change your real files        yes                   no, your files are untouched
Ask the supervisor to send it -                     refused, signed receipt
~~~

Every secret in the demo is a fake made for that run. If the attacks do not land in the
ordinary container, the demo says so and claims nothing.

## Use it on your project

~~~sh
cd my-project
export ANTHROPIC_API_KEY=...    # or OPENAI_API_KEY for Codex
airlock protect "Fix the failing test"
~~~

The first run builds the sealed image and asks you to approve one thing: this agent, this
model, this spend limit for each run. The default limit is $2.00. The key stays on your
machine, outside the container. When the agent finishes, you get what it changed, what was
blocked, what it cost, and a patch you can take with `git apply`. Add `--tests DIR` to check
the change with tests you hold outside the project.

| Agent | Version | Status |
|---|---|---|
| Claude Code | 2.1.308, unchanged | Real binary tested through the real boundary with a scripted model. No scored real-model result yet |
| Codex CLI | 0.166.0, unchanged | Same |
| Aider | 0.86.2, unchanged | Scored with a local model under [acceptance v2](release/acceptance-v2/VERDICT.md). Uses the [guided path](docs/golden-path.md) |

To publish a change, Airlock can create one exact file on GitHub after you approve its exact
bytes, then confirm it by reading it back. See the [golden path](docs/golden-path.md).

Know the limits before you rely on it:

* The agent can send anything in its copy of the project to the model it is allowed to use.
  `.env` files and known credential folders are left out, but a secret in ordinary source
  goes in.
* The container has no network, so the agent cannot install packages. If your tests need
  dependencies, [build them into an image](docs/protected-mode.md#your-projects-dependencies)
  and pass `--image`.
* The agent's work can still be wrong. Airlock limits what it can do, not whether it is right.

## Status

This is a development candidate, version 0.1.0.dev0, and not a release. Nothing is published
to a package registry. Dependencies are pinned to exact source commits, including unmerged
Kernel and Permit candidates, and the [release admission gate](release/README.md) reports NOT
READY. The [release bar](release/RELEASE_BAR.md) sets what a release needs, and the
[checkpoint](release/CHECKPOINT.md) shows where each item stands.

## Protect your own Python agent

This is a separate, lighter path for agents you write yourself. It runs in Local Mode, which
is cooperative Python interception and not a container boundary.

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

## The guided path

`airlock protect` runs the first half of the [ten-step golden path](docs/golden-path.md). Use
the steps directly when you want to see each one, or to publish a reviewed change:

~~~sh
airlock doctor
airlock setup --agent aider --model MODEL --model-endpoint URL --approve
airlock work --message-file ISSUE.md --test-command "python -m pytest -q"
airlock capture
airlock status
~~~

Details for each agent are in [Claude Code](docs/claude-code.md) and
[Codex CLI](docs/codex-cli.md). For stopping, rotating and recovering, see
[operations](docs/operations.md).

## Credentials and receipts

The parent broker retains credentials. In Local Mode, the agent receives opaque handles for GITHUB_TOKEN,
GH_TOKEN, OPENAI_API_KEY, and ANTHROPIC_API_KEY, bound to their standard HTTPS API origins.
Only a verified, authorized request can materialize a handle in an authorization/API-key header.
Unknown environment variables are not inherited; nonsecret configuration inputs observed by
Scan are forwarded. The broker ignores proxy environment variables.
SDK credential-profile discovery is directed to a new, empty per-run directory.
In Protected Mode, the contained agent receives a loopback bridge and dummy model keys;
the supervisor selects the reviewed credential for each supported external operation.

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
and credential/execution flags. Authorization is recorded before the effect; observation gets a
linked completion record. Consequential HTTP uses Permit's durable effect reservation, verified
and claimed independently by Kernel before credential release. Lost responses leave AMBIGUOUS
ownership held, and identical retries remain blocked across new runs and grants. In Local Mode,
read-only classification comes from Scan; those requests remain repeatable. Protected Mode
supports reviewed model inference and exact GitHub file creation. Other outbound calls, including
arbitrary GETs, are denied: an HTTP verb alone does not establish harmless consequences.

A generic HTTP response is returned to the agent, but does not prove the remote consequence
committed. Its signed receipt says `response-received`, `transport_completed: true`,
`outcome: AMBIGUOUS`, and `execution_occurred: null`. The effect remains held. A timeout also
records AMBIGUOUS / OUTCOME_UNKNOWN, never a false statement of non-execution. The local
fingerprint binds method, exact URL, body and caller headers, with stable parent credential
references instead of random credential handles. Source/proof/grant changes do not reset it.
The protected [GitHub create-only profile](docs/github-consequence.md) derives its effect identity
from repository identity, branch, file, content and commit message; trace headers do not reset it.
Its host readback validates exact provider state under a reviewed exclusive-writer assumption.
Other APIs still require their own consequence projection and finality checks.
Use `airlock reconcile <effect-id>` to inspect a held effect. An explicitly approved,
separate observer key can attest `--committed` or `--not-executed`, with evidence bound to
the exact original attempt and the ledger state reviewed. See [reconciliation](docs/reconciliation.md)
for local signing, detached review and the authenticated provider hook. This build does not claim
COMMITTED from HTTP status, cross-host ownership, or complete G1–G40 acceptance.
Generic HTTP receipts retain body hashes. The GitHub profile also retains the exact reviewed
creation body inside the signed authorization receipt so it can be verified after a lost response.
Its readback saves bounded provider bodies privately under `.airlock/local/`; these can contain
private code and GitHub user metadata. Headers and credential values are excluded. Evidence is
not uploaded automatically; review and redact an export before sharing it.
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

## Execution modes

`airlock run` uses Local Mode: cooperative Python interception.
`airlock run --protected -- python3 main.py` requires the outside-process
container boundary and fails closed when it is unavailable. Protected Mode allows
shell, tests/builds and local git in a copied workspace while the external supervisor
retains credentials, keys and effect state. See [Protected Mode](docs/protected-mode.md)
for the candidate image setup, model constraints, evidence and remaining gates.

## Local Mode supported boundary

- Python requests (including PyGithub), httpx sync/async, and urllib.request.
- Generic HTTP authority binds the scheme, host, port, exact path, and query.
- GitHub authority uses Scan's action and repository vocabulary and an HTTPS API origin.
- Requests and responses are buffered, limited to 4 MiB. Redirects are returned without being followed.
- Runtime HTTP must trace to resolved Scan evidence in the project. Unresolved calls cannot inherit
  the authority of a resolved call to the same URL.
- Source lines and columns distinguish callsites. Ambiguous async expressions or source sites
  shared with unresolved evidence remain blocked.
- Adapters are registered by Scan power kind: HTTP and GitHub are executed by the broker.
  Unresolved HTTP methods remain blocked. Process and filesystem effects are released to the
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

The local signed receipt journal serializes appends across threads and broker
processes. An interrupted partial record stops further appends until recovery;
evidence is preserved. See [the journal attack evidence and guarantees](docs/evidence/receipt-journal/README.md).

### Codex CLI integration candidate

[Run unchanged Codex CLI inside Protected Mode](docs/codex-cli.md). The pinned
Responses integration has a scripted real-binary rehearsal and independent Docker
controls. Live-model acceptance is not yet run; historical release gates still apply.
