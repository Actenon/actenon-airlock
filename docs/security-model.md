# Security model

Airlock makes several separate guarantees. Each rests on something different and covers a
different threat, so they are listed separately here rather than as one claim of "safety".
Read [what is not covered](#what-is-not-covered) before you rely on any of them.

## 1. Protected container execution

**What it does.** `airlock protect`, `airlock demo` and `airlock run --protected` run the agent
in a Docker container on this machine with no network interface other than loopback, a
read-only root, user 10000, no Linux capabilities, no-new-privileges, Docker's default seccomp
filter, private process namespaces, a process limit, 1 GiB of memory and two CPUs. The only
writable host mount is a fresh copy of the project. Your real project, your home folder, the
Docker socket and Airlock's own state are never mounted.

**What it rests on.** The Linux kernel's isolation as configured by Docker, and Airlock refusing
to start on a remote engine, a non-Linux engine, or one without seccomp.

**Where it is tested.** The real-container suites in CI (`Protected container acceptance`) and
`tests/test_independent_container.py`, which checks containment with an independent listener.
`airlock demo` Part 1 shows it on your machine against a control that leaks.

## 2. Credential isolation

**What it does.** Model keys and tokens stay in the supervisor process on your machine. The
agent gets a loopback bridge and dummy keys. `.env` files and known credential folders are not
copied into the workspace, and host subprocesses get an explicit, minimal environment.

**What it rests on.** Protected container execution (1), and the supervisor selecting the
credential for each approved operation itself.

**Not covered.** A secret in ordinary source code is copied, and the agent can send it to the
model you allowed.

## 3. Parameter-bound authority

**What it does.** Approval signs exact powers, not categories: for a model, the endpoint,
model names, the request format, size and output bounds, prices and the spend limit; for a
GitHub write, the repository, branch, path, parent commit and the exact bytes. Every request is
checked against the signed approval before the credential is attached. Anything else is
refused with a signed receipt. Powers that Scan finds in your code are shown, but for a
protected agent only the model route and separately reviewed GitHub creations are ever
signed; the rest are listed as found but not granted.

**What it rests on.** Ed25519 signatures over the approval, Actenon Permit's grant decisions
and Actenon Kernel's verification, with the signing key kept in `.airlock/local/` on your
machine.

**Not covered.** An attacker who controls your user account or the signing key.

## 4. Spend bound

**What it does.** Before each model call Airlock reserves the call's worst-case cost from the
signed prices and output bound, and refuses the call if that could exceed what is left of the
per-run limit. Nothing is sent for a refused call.

**What it rests on.** The prices you approve. Airlock does not read your provider's bill: the
spend it reports is an estimate from the usage the provider returns, and a call whose answer
never arrives is counted at its worst case.

## 5. Effect reservation

**What it does.** A consequential request (a GitHub file creation, or a consequential HTTP request in Local
Mode) reserves its effect before it is sent. An identical request is refused while the first
is unresolved, across runs and new approvals. A lost response leaves the effect AMBIGUOUS and
held; Airlock never retries it blindly.

**What it rests on.** Permit's durable reservation, claimed independently by Kernel before the
credential is released.

## 6. Evidence integrity

**What it does.** Every decision is a signed, hash-chained record in
`.airlock/local/receipts.jsonl`. `airlock receipts` verifies the chain; `airlock checkpoint` and
`airlock verify-evidence` let you keep a copy outside the project and check it later.

**Not covered.** A signed receipt says what Airlock decided and observed. It is not proof of
what a remote provider did; that is the next item.

## 7. Independent consequence verification

**What it does.** A GitHub file creation counts as done only after Airlock reads GitHub back and
finds the exact bytes, path and parent. Until then it is AMBIGUOUS. `airlock reconcile` can
settle a held effect from provider readback, or from a separately approved observer.

**What it rests on.** The provider's own state, read with a credential the agent never had,
under a reviewed exclusive-writer assumption for that branch and path.

**Where it is shown.** `airlock demo` Part 2, against Airlock's local stand-in for GitHub, with
an independent check of the stand-in's own record. The demo does not write to real GitHub.

## Local Mode is different

`airlock run` without `--protected` uses Local Mode: cooperative interception of Python HTTP
clients and audit hooks in the agent's own interpreter. It enforces approved powers for agents
you write yourself, but it is **not a sandbox for hostile code**. Native extensions, other
languages, raw sockets and an attacker with your user account are outside it. Use Protected
Mode for an agent you do not trust.

## What is not covered

- Whether the agent's change is correct. Read the patch.
- Secrets in ordinary source files.
- An attacker with control of your user account, Docker, or `.airlock/local/`.
- Kernel or Docker escapes.
- External services other than the approved model and reviewed GitHub file creations: other
  HTTP APIs, payments, databases and MCP tools are refused in Protected Mode, not supported.
- Billing settlement: spend figures are estimates from reported usage.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
