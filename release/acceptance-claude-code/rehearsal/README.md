# Rehearsal, not evidence

These files come from one rehearsal of the whole programme at commit `6ebb639`, from a clean tree. The model was a scripted endpoint, and the task fixes were the known reference solutions replayed by that script. **Nothing here is a scored result, and the scorer refuses to count it.**

It shows that the harness, boundary and evidence path work with the real Claude Code binary. It shows nothing about what a real model would do, so its PASS rows only mean the scorer can reach them. `programme.json` records its status as `NOT READY`.

| File | What it holds |
|---|---|
| `programme.json` | The scorer's output, marked `REHEARSAL, NOT EVIDENCE` |
| `controls.json` | Fixed abuse attempts from the Claude Code image, with the unrestricted positive control. No model is involved, so the observations are real, but the run was not under the freeze |
| `contract.json` | Out-of-contract model requests from inside the container. No model is involved here either |
| `flagship-summary.json` | Outcomes A to D, computed from independent artifacts |
| `flagship-transcript.txt` | Every command and its output |

The temporary run directory is shown as `<rehearsal>`.
