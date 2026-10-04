# Protected Mode development candidate

`airlock run --protected` requires a local Linux Docker engine. It never falls
back to Local Mode. `airlock doctor` distinguishes the two guarantees.

Local Mode intercepts cooperative Python calls. Protected Mode allows Python,
shell, tests/builds, nested processes and local git inside a copied workspace.
It installs no Python security hooks in that agent. Its external boundary lives
in the host supervisor and Linux isolation, beyond the agent's interpreter.

## Run the candidate

Build the credential-free compute image once, from the pinned official Python
image and published packages:

```sh
docker build -f containers/Dockerfile.compute -t actenon-airlock-compute:dev .
airlock doctor
airlock init --approve --command 'main.py' --model my-approved-model --model-max-tokens 2048
airlock run --protected -- python3 main.py
```

The model inference endpoint must also be present in Scan's resolved powers.
The model option narrows that power; it cannot create HTTP authority. Anthropic
uses `--model-provider anthropic`. Credentials go only in the supervisor's
environment. The contained SDK receives a loopback endpoint and a dummy key.
The parent binds the normalized exact body, credential reference and target
before Permit mints the proof and Kernel executes the request.

This preview supports text inference, exact model names, a 64 KiB input bound
and at most the approved output bound (1–4096 tokens). Missing output limits
are filled with the approved bound **before** hashing, verification and dispatch.
Remote tools, stored state, attachments, extra outputs and unknown parameters
are refused. A valid completed model response with usage establishes observed
inference output; it does not establish billing settlement or downstream effects.
Other consequential HTTP remains AMBIGUOUS after a transport response.

Compute images must be trusted and credential-free. `--image` selects a local
image; the supervisor resolves its immutable content ID, disables healthchecks,
clears inherited environment values and refuses image-declared extra volumes.
Agent requirements belong in that image, prepared before a protected run.
Automatic image preparation and registry-only installation remain release gates.

## Boundary and authority

The agent has a read-only root, UID 10000, no Linux capabilities, no-new-privileges,
Docker's default seccomp protection, private PID/IPC namespaces, no external
network, a 128-process limit, 1 GiB memory and two CPUs. Its only writable host
mount is a newly copied workspace. Private container device/shared-memory scratch
is compute space; the original project, host home, Docker socket and trusted
state are never mounted. This preview has no workspace disk quota.

A separate network-disabled bridge exposes only a Unix socket in a volume the
agent mounts read-only. That socket carries bounded JSON data through attached
Docker stdio to the host supervisor. The bridge has no credentials, policy,
signing keys or effect store. The supervisor inspects actual container settings,
including exact mount sources, before either container starts.

Agent code can replace its own proxy, cwd, environment or fake `.airlock` files.
Those do not affect the supervisor. Approval/reconciliation RPCs do not exist.
Raw sockets, nested children and git cannot obtain an alternate network path.
HTTP uses the existing Scan vocabulary and the signed manifest's approved powers;
Permit decides and Kernel verifies the exact action at the execution callback.
Unknown methods do not become any-method grants. Undecomposed GitHub GraphQL
remains blocked in Protected Mode until Scan supplies safe consequence semantics.

All contained code shares one grant principal. The supervisor never trusts a
caller-supplied filename as an attestation of origin. Provenance comes from the
signed code manifest, whose digest is bound into the grant principal and included
with signed receipts. New target/action/transport tuples remain outside the grant.
CI compares model expansions as well as code powers against the trusted base.

## Results and honest evidence

Runs preserve boundary configuration and completion facts under
`.airlock/local/runs/<run-id>/`. Work remains in that run's copied workspace;
the original project is not automatically modified. `.git` history/config/hooks,
`.env*`, host credential directories and `.airlock` are excluded from input.
Regular bytes are copied using directory descriptors and no-follow checks;
links/special files, oversized input and embedded bound credentials are refused.
The source snapshot must equal the reviewed runtime discovery.

Input code and images must be free of other unknown embedded secrets. This is
not a general secret-discovery claim. Treat generated output, links and local git
hooks as untrusted; do not execute them on the host when reviewing results.

Every **broker decision** has a signed receipt, exact target, grant and execution
flags. OS denials do not pretend to be individually observed/signed syscalls.
The container acceptance test separately verifies free compute and alternate-route
refusals from one environment. Its model response is an explicit deterministic
provider fixture using the real OpenAI SDK and real Scan/Permit/Kernel; it is
not an external coding-agent acceptance run or a live model-quality demonstration.

The useful external coding-agent workflow, three original and ten total agent
cases, PostgreSQL/MCP/GraphQL boundaries, cumulative budgets, portable verifier
parity and fresh public-artifact installation remain open G1–G40 gates. This
candidate does not declare Airlock v1 finished or a universal OS jail.
