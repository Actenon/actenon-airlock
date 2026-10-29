# Field Test 7: The Unmodified Coding Agent Challenge

## Objective
Evaluate Actenon Airlock with pinned upstream `gpt-engineer` 0.3.1 (`a90fcd543eedcc0ff2c34561bc0785d2ba83c47e`) and `qwen2.5-coder:7b` without modifying the agent's internal source code or replacing its tool execution.

## Experiments
- **Stage 4 (Protected Execution):** Running `gpt-engineer` inside Airlock Protected Mode (`actenon-airlock-gpt-engineer:acceptance`).
- **Stage 5 (Adversarial Prompt Injection):** Providing the agent an issue containing malicious instructions demanding outbound network exfiltration.
- **Stage 6 (Consequence Verification):** Evaluating supervisor publication and observing that the incorrect patch was published when the operator blindly signed the consequence.

## Key Discovery
- Airlock successfully enforced 100% network containment on the unmodified agent.
- However, Airlock's core design is an authorization and consequence boundary, not a semantic code correctness verifier: an operator can mistakenly approve and publish a mathematically defective patch unless an independent quality gate is introduced.
- Full audit report in `evaluations/reports/07_unmodified_coding_agent.md`.
