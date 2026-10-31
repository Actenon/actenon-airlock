# Live Claude Code run (owner authorization required)

**Status: prepared, not run.** Every run so far used a scripted endpoint, so nothing has been billed. A scored run makes real, billable Claude API calls.

## Why a subscription cannot be used

A Claude subscription is not a supported path for this programme, and Airlock refuses subscription tokens.

- Protected Mode requires that the agent container hold no credential, so the supervisor would have to hold the token and attach it to the agent's requests.
- [Claude Code's legal and compliance page](https://code.claude.com/docs/en/legal-and-compliance) says developers may not "collect, store, or intermediate Claude.ai credentials or session tokens". It reserves those credentials for an end user signing in to the unmodified binary.
- A login inside the container would satisfy that rule but break Protected Mode, because a prompt-injected agent could read the token.

The docs do not address a trusted local proxy holding the owner's own token. This reading is therefore a conservative interpretation. For a definitive answer, the page says to contact sales. Using a subscription here would need that answer in writing, not a workaround.

## What it needs

An API key from the [Claude Console](https://platform.claude.com), billed separately from any subscription. The key stays in the supervisor's environment and on the host-side baseline gateway. No container receives it.

Use a dedicated workspace with its spend limit set to the figure you authorize. That gives an outer limit enforced by Anthropic, independent of everything here.

## Cost

Prices below are the published first-party rates as of 2026-10-06. Check them against the [pricing page](https://platform.claude.com/docs/en/about-claude/pricing) before authorizing, and update `PRICES` in `run_task.py` if they differ.

| Model | Input | Cache write | Cache read | Output |
|---|---|---|---|---|
| `claude-opus-5-5` (programme default) | $4 | $5 | $0.20 | $20 |
| `claude-sonnet-5-5` | $2 | $2.50 | $0.20 | $10 |

All per million tokens. Cache write is the documented ~1.25x of input.

| Scope | Runs needing a model | Hard cap at $2.00 per run |
|---|---|---|
| First slice: `--only flagship` | 1 | $2.00 |
| Whole programme | 31 | **$62.00** |
| Fixed controls and contract abuse | 0 | $0 |

The 31 runs are 20 task runs, 2 poisoned-repository runs, 8 induced-attack runs and 1 flagship journey.

**The cap is the bound, not a forecast.** No live run has happened, so real cost per run is unknown. Measure it on the first slice before authorizing the rest.

## How the cap holds

| Run | What enforces $2.00 |
|---|---|
| Protected | The supervisor, from signed prices. It reserves each call's worst case before any byte leaves and refuses a call that would pass the bound |
| Baseline | `gateway.py` on the host, the same way |

Spend figures are estimates from provider-reported usage, not billing settlement. Claude Code's own `--max-budget-usd` also runs, but it is an estimate inside the agent's process, so nothing relies on it. A run can stop early at its bound, which would show up as an unsolved task.

## To run it

`config.json` is frozen for `claude-opus-5-5` on the machine that built these images. A freeze pins local image IDs, so a scored run refuses any drift. To use another model or machine, write a new config from a clean checkout before any scored run, then use it in the commands below:

```bash
python acceptance/claude-code/run_task.py freeze --model claude-sonnet-5-5 --output /tmp/claude-code-config.json
```

Run the free controls and the first slice:

```bash
ANTHROPIC_API_KEY=YOUR_KEY python acceptance/claude-code/claude_programme.py run --config release/acceptance-claude-code/config.json --model claude-opus-5-5 --only controls --out /tmp/cc-programme
```

```bash
ANTHROPIC_API_KEY=YOUR_KEY python acceptance/claude-code/claude_programme.py run --config release/acceptance-claude-code/config.json --model claude-opus-5-5 --only contract --out /tmp/cc-programme
```

```bash
ANTHROPIC_API_KEY=YOUR_KEY python acceptance/claude-code/claude_programme.py run --config release/acceptance-claude-code/config.json --model claude-opus-5-5 --only flagship --authorized-usd 2.00 --out /tmp/cc-programme
```

Then the rest, once you are content with the first slice's cost:

```bash
ANTHROPIC_API_KEY=YOUR_KEY python acceptance/claude-code/claude_programme.py run --config release/acceptance-claude-code/config.json --model claude-opus-5-5 --authorized-usd 60.00 --out /tmp/cc-programme
```

Score it:

```bash
python acceptance/claude-code/claude_programme.py score --config release/acceptance-claude-code/config.json --out /tmp/cc-programme --evidence release/acceptance-claude-code/evidence
```

Each run stays one at a time, and finished runs are kept and skipped, so an interruption resumes rather than rebills. Failed and partial runs stay in the evidence.
