# Claude Code acceptance verdict

**Status: NOT READY. Not run.** No scored run has happened, because the programme needs billable inference that has not been authorized. No designation is awarded, and G1-G40 and acceptance v2 are unchanged.

## What is established

These come from tests and a scripted rehearsal. They show the integration works. They do not show what a real model would do.

| Finding | Evidence |
|---|---|
| The unmodified Claude Code 2.1.308 binary completes a read, edit and run loop inside Protected Mode | `tests/test_claude_code_container.py`, real binary and real containers |
| The container holds no real credential, and its tools reach no network or host | Same tests |
| Provider-executed tools, remote MCP and URL sources are refused before dispatch | `tests/test_agent_inference.py` and `attacks.py contract` |
| A tool call in a model reply authorizes nothing | Same tests |
| A lost reply stays held and counted, and the client's retry is not sent | Same tests |
| With relay keepalive, the client waits through a silent 400-second reply and makes one call. Without it, a 6-minute reply was lost | One manual run and [one real-model diagnostic](../../docs/evidence/local-model-diagnostics/README.md), not in the suite |

The programme is frozen in [`config.json`](config.json). A full [rehearsal](rehearsal/README.md) with a scripted model ran all 33 entries from a clean tree. It is not evidence, and the scorer refuses to count it.

## What is not established

- Whether a real model does useful work inside the boundary. [Three local-model diagnostics](../../docs/evidence/local-model-diagnostics/README.md) ran through it, and none made a tool call.
- Whether a real model obeys the injected instructions.
- Real cost per run.
- Whether the contract covers everything a real model produces. Real replies include thinking blocks and longer conversations that the scripted endpoint does not. The contract fails closed, so a gap would show up as a refused call, not an escape.
- Whether 1 GiB of memory is enough for a long real session. The docs list 4 GB or more for Claude Code. Short scripted runs fit in the limit.
- Any live GitHub result. The provider in C1, C2 and R1 is synthetic.

## Requirements

Every requirement in the [specification](spec.json) is **not yet evaluated**.
