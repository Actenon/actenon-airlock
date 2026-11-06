# Actenon Airlock

**Give an AI coding agent real work, without giving it your keys, your machine or the power
to act beyond what you approve, and check what actually happened.**

Your unchanged agent (Claude Code or Codex CLI) works on a copy of your project inside a
sealed container: no network, no credentials, no home folder. Its only way out is Airlock,
which lets through exactly what you approved, such as calls to one model up to a spend
limit, and refuses everything else with a signed receipt. You get a patch to review and a
receipt that says only what was observed.

## Install

You need macOS or Linux, Python 3.11 or newer, Git, [pipx](https://pipx.pypa.io) and Docker
running. Not sure? `airlock doctor` checks everything after the install.

~~~sh
pipx install "git+https://github.com/Actenon/actenon-airlock.git@733bd48bb391cc4e7fee1c3810bc22b79d0d2c9a"
airlock doctor
~~~

This installs one exact, reviewed commit of the development candidate, together with the
other Actenon components it needs at their pinned commits. Airlock is **not on PyPI yet**
and this is **not a release**. No pipx? `brew install pipx` on macOS, `sudo apt install pipx`
on Debian or Ubuntu, or use a virtual environment:

~~~sh
python3 -m venv ~/.airlock
~/.airlock/bin/pip install "git+https://github.com/Actenon/actenon-airlock.git@733bd48bb391cc4e7fee1c3810bc22b79d0d2c9a"
~/.airlock/bin/airlock doctor
~~~

A plain `pip install` into Homebrew's or the system Python is refused (PEP 668); that is why
the commands above use pipx or a virtual environment. Problems: [troubleshooting](docs/troubleshooting.md).

## See it work: free, no key, no account

~~~sh
airlock demo
~~~

**Part 1.** A script does a small job, then acts like a hijacked agent. It runs once in an
ordinary container and once in Protected Mode. The results come from what actually reached
an independent listener:

~~~text
                              Ordinary container    Protected Mode
Fix the bug                   done                  done, as a patch to review
Steal the GitHub token        LEAKED                nothing got out
Steal the project's .env      LEAKED                nothing got out
Steal the SSH private key     LEAKED                nothing got out
Send data straight out        LEAKED                nothing got out
Change your real files        yes                   no, your files are untouched
Ask the supervisor to send it -                     REFUSED, signed receipt
~~~

**Part 2.** The fix from the sealed run goes through the path a real publish uses. Your tests
check it in a sealed container. You see the one exact grant it needs. Airlock refuses an
edited copy and a write to another file, sends the approved write once and refuses a replay.
It counts the write as done only after reading the result back, and an independent check
agrees:

~~~text
RECEIPT
  Changed    1 file (calculator.py)
  Checked    PASS: 2 tests passed
  Approved   1 exact file creation, nothing else
  Refused    3 attempts, none reached the stand-in
  Happened   1 file created on the local stand-in, confirmed independently
  Uncertain  nothing
  Evidence   12 signed receipts, integrity OK
~~~

The secrets are fakes made for the run, and "GitHub" in Part 2 is Airlock's local stand-in;
nothing is written to real GitHub and nothing leaves your machine. If the attacks do not land
in the ordinary container, or any line is not backed by evidence, the demo says so and claims
nothing. The first run builds a small image; after that it takes a few seconds.

## Use it on your own project

~~~sh
cd my-project
export ANTHROPIC_API_KEY=...       # or OPENAI_API_KEY for Codex CLI
airlock protect --tests ../my-project-tests "Fix the failing test"
~~~

1. **Review.** Airlock shows, in plain words, the one thing you are asked to approve: this
   agent may call this model, up to a spend limit per run ($2.00 unless you choose another),
   with every bound listed. Powers Airlock finds in your code, such as a call to `xdg-open`,
   are listed as *found but not granted*. Nothing runs until you say yes.
2. **Work.** The agent works on a copy in the sealed container. You see short progress lines;
   anything it says about itself is labelled as its own claim. The key stays on your machine.
3. **Check.** With `--tests DIR`, your own tests, held outside the project, check the change in
   a sealed container. The check commands come from your project, never from the agent's copy:
   pytest for Python, `go vet` and `go test` for Go, `tsc` and `vitest` (or `npm test`) for
   TypeScript. The result is PASS, FAIL, SKIPPED, UNSUPPORTED or INCONCLUSIVE, and skips or
   edited test settings never count as a pass unless you say so.
4. **Receipt.** What changed, what the checks found, what was refused, what it cost and what is
   still uncertain. A run stopped by the spend limit says so instead of looking finished.
5. **Take it or leave it.** Your project is untouched. Apply the patch with the `git apply`
   command the receipt prints.

Go and TypeScript checks need an image with your toolchain. Airlock checks for it before the
agent runs and prints the one command that builds it. See [real projects](docs/real-project.md)
and the step-by-step [getting started](docs/getting-started.md) guide.

| Agent | Version | Status on this candidate |
|---|---|---|
| Claude Code | 2.1.308, unchanged | Real binary through the real boundary in CI with a scripted model. Live-model runs exist for earlier candidates; none is a formal result for this one |
| Codex CLI | 0.166.0, unchanged | Same, with a scripted model |
| Aider | 0.86.2, unchanged | Scored with a local model under [acceptance v2](release/acceptance-v2/VERDICT.md); uses the [guided path](docs/golden-path.md) |

## What Airlock does and does not promise

| | |
|---|---|
| **Enforced** | In Protected Mode the agent has no network, no credentials and no route to your home folder. Only approved model calls and reviewed GitHub file creations leave, each bound to exact parameters you signed. Other requests are refused, with a signed receipt. |
| **Kept from the agent** | API keys and tokens stay with Airlock on your machine. `.env` files and known credential folders are not copied in. |
| **Recorded** | Every decision is in a signed, hash-chained journal that `airlock receipts` verifies. |
| **Confirmed only by readback** | An external effect counts as done only after Airlock reads the provider back. A lost response stays AMBIGUOUS and identical retries stay blocked. |
| **Not promised** | That the agent's work is right. That a secret written in ordinary source stays private: the agent can send anything in its copy to the model you allowed. Local Mode (`airlock run`) is cooperative Python interception, not a sandbox for hostile code. |

The full list, with what each guarantee rests on, is in the [security model](docs/security-model.md).

## Status

Development candidate 0.1.0.dev0. **Not a release and not on any package registry.** It depends on
exact source commits of Actenon Scan, Permit, Kernel and Protocol, some of them unmerged
candidates ([pins](evidence/dependency-pins.json)). The [release admission gate](release/README.md)
reports NOT READY; the [release bar](release/RELEASE_BAR.md) says what a release needs and the
[checkpoint](release/CHECKPOINT.md) shows where each item stands.

Questions, bugs and offers to test it: [contributing](CONTRIBUTING.md).

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
