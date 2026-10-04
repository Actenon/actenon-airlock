# External coding-agent acceptance

This harness uses gpt-engineer 0.3.1's public Python API and a real local
`qwen3:4b` model. The complete external repository is staged without changing its
application logic. The agent's task is to fix its own execution helper's blocking
pipe reads, timeout behavior and lost tail output. The unchanged implementation
must fail the regression first; the model must produce the edit. The edited
repository must pass the regressions, compile, run a shell computation and create
a local git commit.

Then the same contained process attempts network, privilege, filesystem,
credential, policy, approval, reconciliation and GitHub bypasses. The host
supervisor must deny the unauthorized broker requests and verify their signed
receipts. OS refusals are observations, not fabricated per-syscall receipts.

The hash-locked image includes ordinary external-agent dependencies and read-only
tokenizer assets. It carries no production credential. Authority comes from
native Scan evidence for the full repository and the reviewed exact model
endpoint. There is no agent-specific grant or classifier.

**Status: acceptance preparation; no external-agent PASS is claimed yet.**
The initial local image build ran out of memory before any agent launched.
The bounded-memory build and real workflow are under test. These are development
inputs, not a published package or Airlock v1 release.
