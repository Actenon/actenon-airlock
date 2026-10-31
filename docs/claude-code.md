# Claude Code in Protected Mode

Airlock runs the unchanged Claude Code CLI inside Protected Mode. The agent keeps its normal tools in a disposable workspace. Its model calls go through the supervisor, which holds the API key, and any external consequence still needs an exact approval.

**Status: integration candidate.** The real binary works through the real boundary against a scripted model. It has no scored live result yet, so `airlock doctor` reports it as a candidate. See the [verdict](../release/acceptance-claude-code/VERDICT.md).

## Get started

Build the images once, in a trusted environment:

```bash
docker build -f containers/Dockerfile.compute -t actenon-airlock-compute:dev .
```

```bash
docker build -f containers/Dockerfile.claude-code -t actenon-airlock-claude-code:v1 .
```

Check what is ready:

```bash
airlock doctor
```

Review the agent's authority, then approve it. Prices are USD per million tokens, in the order input, cache write, cache read, output. Airlock will not guess them, because they set the spend bound:

```bash
airlock setup --agent claude-code --model claude-opus-5-5 --max-run-usd 2.00 --price-per-mtok 4,5,0.2,20
```

```bash
airlock setup --agent claude-code --model claude-opus-5-5 --max-run-usd 2.00 --price-per-mtok 4,5,0.2,20 --approve
```

Give the agent a task from a file in the project. The API key stays in the supervisor's environment:

```bash
ANTHROPIC_API_KEY=YOUR_KEY airlock work --message-file ISSUE.md
```

The rest is the [golden path](golden-path.md): `capture`, `verify-candidate`, `review-candidate`, `publish`, `status`.

## Authentication

Use an API key from the Claude Console. It is billed separately from any Claude subscription.

Host-local Claude state is withheld from the workspace, including `.credentials.json`, `.claude.json` and `settings.local.json`. A project's own `CLAUDE.md` and `.claude/settings.json` are copied, because they are project content the agent is meant to read. They are also untrusted input.

Airlock refuses a subscription token. Protected Mode keeps credentials out of the container, so the supervisor would have to hold the token and attach it, and [Claude Code's terms](https://code.claude.com/docs/en/legal-and-compliance) say developers may not "collect, store, or intermediate Claude.ai credentials or session tokens". The container gets a placeholder key instead, and the supervisor replaces it.

## What the agent can do

| In the workspace | Through the supervisor | Refused |
|---|---|---|
| Read, edit and write files | Calls to the one approved model | Any other network route |
| Run shell commands and tests | One exact approved GitHub creation | Provider-executed tools |
| Use local git | | Anything else outbound |

The agent runs with `Bash,Read,Edit,Write,Glob,Grep`. Permission prompts are off because Airlock, not the client's own prompts, is the boundary. `WebFetch` and `WebSearch` are left out, since one has no network and the other is a provider-executed tool.

## The inference contract

`anthropic-agent/v1` is the set of request and reply shapes the pinned client uses. Anything else is refused, because some Messages API features make the provider itself act:

| Refused | Why |
|---|---|
| Server tools such as web fetch, web search and code execution | The provider would fetch URLs or run code for the agent |
| `mcp_servers` and `container` | The provider would reach remote systems |
| Image and document URL or file sources | The provider would fetch content, and a URL can carry data out |
| Beta features outside the signed list | Several switch on the routes above |
| Any model outside the signed list | Model authority is exact |

Anthropic's gateway guidance says to forward beta headers without an allowlist. Airlock deliberately does not, because it is a security boundary rather than a pass-through. A new Claude Code version may therefore need a reviewed update to its list.

Bodies are forwarded byte for byte after a strict parse. Replies are checked whole before the agent sees them, so a tool call reaches the agent as data and authorizes nothing. This means responses arrive all at once rather than streaming.

## Spend and failure

The supervisor enforces `--max-run-usd` from the signed prices. It reserves each call's worst case before any byte leaves, then replaces that with the reported usage. Figures are estimates, not billing. Claude Code's own `--max-budget-usd` also runs, but it is inside the untrusted process, so nothing relies on it.

| Reply | What happens |
|---|---|
| Complete and in contract | Confirmed. An identical later request is a new call |
| Explicit 429 or 529 | The call ended, so the client's retry is a new call. Its effect stays unconfirmed, because the reply proves nothing about billing |
| Lost, cut off, 5xx or malformed | Unconfirmed and still counted. An identical retry is refused, so the run usually ends |

## Limits

- A long real session may need more than the 1 GiB container limit. Claude Code's docs list 4 GB or more.
- Requests run one at a time through the bridge.
- A pinned image and its signed beta list go together. Updating Claude Code means rebuilding, reviewing and re-approving.
- Other `airlock` guarantees and limits are in [Protected Mode](protected-mode.md) and [Operations](operations.md).
