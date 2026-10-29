# Frozen real-model acceptance history

Every recorded run of `real-coding-acceptance.yml` (gpt-engineer at
`a90fcd543eedcc0ff2c34561bc0785d2ba83c47e`, its own regression test for
`disk_execution_env.py`) has failed. Diagnosed on 2026-10-29 from each run's
failed-step log and, for runs 6–8, the uploaded baseline evidence.

| # | Run | Head | Model | Failed step | Observed cause | Category |
|---|---|---|---|---|---|---|
| 1 | [37245194446](https://github.com/Actenon/actenon-airlock/actions/runs/37245194446) | `b7531941` | qwen3:4b | Protected task | Inference read exceeded Airlock's fixed 30 s; the call was held `AMBIGUOUS` and later inference refused (403) | Airlock configuration: fixed timeout (since made a reviewed 1–600 s setting) |
| 2 | [37282985403](https://github.com/Actenon/actenon-airlock/actions/runs/37282985403) | `01e7de59` | qwen3:4b | Protected task | After the reviewed 600 s read, the model was still generating reasoning text past its context; held `AMBIGUOUS` | Model behaviour; Airlock held the ambiguous call as designed |
| 3 | [37285768855](https://github.com/Actenon/actenon-airlock/actions/runs/37285768855) | `ef02feae` | qwen2.5-coder:3b | Protected task | `IndentationError` in the agent's edit | Model output |
| 4 | [37287365835](https://github.com/Actenon/actenon-airlock/actions/runs/37287365835) | `f656a305` | qwen2.5-coder:7b | Protected task | Agent never edited the implementation | Model output |
| 5 | [37290106747](https://github.com/Actenon/actenon-airlock/actions/runs/37290106747) | `c6721f6b` | qwen2.5-coder:7b | Protected task | `IndentationError` ×3 | Model output |
| 6 | [37293241687](https://github.com/Actenon/actenon-airlock/actions/runs/37293241687) | `48e74842` | qwen2.5-coder:7b | **Unprotected baseline** | `IndentationError` ×3 | Model output, without Airlock |
| 7 | [37295234658](https://github.com/Actenon/actenon-airlock/actions/runs/37295234658) | `3da414c6` | qwen2.5-coder:14b (frozen) | **Unprotected baseline** | `IndentationError` ×3; diffs copy gpt-engineer's displayed line numbers, so hunks fail to apply | Model + upstream diff format, without Airlock |
| 8 | [37300006802](https://github.com/Actenon/actenon-airlock/actions/runs/37300006802) | `57eefe90` | qwen2.5-coder:14b (frozen) | **Unprotected baseline** | One `IndentationError` attempt, then the frozen 2400 s phase limit on a 2-vCPU runner | Execution time + model output |

## Conclusion

With the frozen 14B configuration, the unprotected baseline fails before
Airlock is involved: the model's diffs do not apply cleanly to gpt-engineer's
numbered file view, and CPU-only inference on a standard runner is slow enough
to hit the frozen phase limit. No run shows an Airlock defect after the run-1
timeout fix. Under the frozen rules a protected result cannot count until the
matched baseline passes, so a rerun is expected to FAIL unless the model's
output differs. The task, model, scoring rules and limits stay as frozen.

The harness's matched baseline is registered for Linux host networking
(`baseline.py` asserts `sys.platform == "linux"`), so it cannot be reproduced
on macOS without changing the harness.
