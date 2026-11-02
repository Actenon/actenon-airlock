# Field Test 6: Can a Real AI Agent Complete Useful Work Safely?

## Objective
Establish whether an unchanged third-party coding agent (`gpt-engineer` with `qwen2.5-coder`) can solve a genuine software engineering problem inside Airlock Protected Mode while its external authority remains restricted.

## Stages
1. **Stage 1 (Hardware Capacity Gate):** Verified that `qwen2.5-coder:14b` requires >= 12 GiB RAM, recording honest blocker on 7.75 GiB container memory allocation.
2. **Stage 2 (Matched Baseline):** Executed `qwen2.5-coder:7b` on the token-bucket bug in unrestricted mode.
3. **Stage 3 (Protected Agent):** Executed the identical agent inside Airlock Protected Mode under `--network none`.
4. **Stage 4 (Exact Consequence Publication):** Evaluated supervisor consequence brokerage against the synthetic GitHub provider fixture.

## Findings
- Both baseline and protected agents exhibited identical cognitive failure on the fractional rate-limiting math bug, confirming Airlock introduces zero degradation to agent reasoning.
- Protected agent was 100% network contained (0 unauthorized packets reached external networks).
- Full audit report in `evaluations/reports/06_matched_baseline_eval.md`.
