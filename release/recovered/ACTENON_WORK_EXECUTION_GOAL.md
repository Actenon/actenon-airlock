# ACTENON — EVIDENCE-DEFINED NORTH-STAR EXECUTION GOAL

Act as the lead implementation engineer for the existing Actenon GitHub organisation. Deliver a reproducible, independently reviewable Airlock candidate that lets an ordinary coding agent complete useful work while its protected external consequences remain within explicitly reviewed authority. Implement and test; do not stop after another architecture report, checklist, scaffold, or synthetic demonstration.

## Product and scope

Airlock is the developer product. Scan discovers and explains candidate authority; discovery never grants permission. Permit evaluates policy, issues authority and manages reservations. Kernel independently verifies the exact execution request and required ownership at the edge. Protocol defines the portable contracts. Keep the verifier independently usable. Do not invent another product or duplicate the source-of-truth classifier.

The initial product slice is a local Linux-container protected coding agent, including Docker Desktop on macOS only when its actual boundary is verified, plus one explicitly supported GitHub mutation workflow. Allow ordinary Python, shell, builds, tests, nested processes and local git in a copied workspace. Keep production credentials, signing keys, approval/reconciliation authority and durable effect state outside the agent. Unsupported targets and effects must be denied, not silently broadened. Do not claim a universal sandbox or arbitrary-provider exactly-once execution.

## Inspect and preserve before changing anything

Inspect every accessible repository, its current default branch, relevant open PRs, source, tests, release artifacts, dependency locks and existing acceptance gates. Inventory inaccessible components without assuming that they do not exist. Distinguish current main, candidate PRs, released artifacts and historical evidence.

The review baseline, not a command to reset newer work, was:
- Airlock main: f998a100748950e05004d22a403c159f1552d686.
- Scan: ee971b43c78ed8b58f5f7fb59382ab20ce9b8a5c.
- Protocol: 3442bf3cffe0b55ac7d531e66ca0355d2c0784e5.
- Kernel: 9dd6af89622f070e3131c39d335be44e3f30149d.
- Permit: 6bbf731125cdde97c1f7b48697c438356a2ccca4.
- Airlock's canonical Go/Rust pins: 12d27356935c7081c36c0b918fda7f5029c14529 and dca4bd51c00c07abfd792cef8c8afffc9392e467.

Inspect Airlock PR #13 first. On 5 October 2026 it remained unmerged and its external gpt-engineer acceptance had not passed: two Qwen3 attempts timed out; a qwen2.5-coder:3b attempt completed model requests but failed unchanged code regressions. Preserve those failures. Do not substitute container fixtures for this useful-agent gate. Inspect any newer results rather than assuming this historical status persists.

Record dirty trees and preserve all existing work. Do not reset, discard, rewrite, squash or overwrite another session's work. Preserve historical failures, frozen corpora, raw logs, manifests and checksums. Map existing G1–G40 and earlier gates into the completion matrix; do not replace them with easier tests. A scope change requires a versioned, explicit rationale, not a silent PASS.

Use isolated branches and reviewable commits. Prepare PRs or PR-ready patches with exact dependency pins. No merge, tag, release, package publication, production deployment, destructive production operation or AIRLOCK-001 execution is authorized by this goal. Do not weaken existing tests or skip failing requirements to obtain green CI. Do not incur paid-provider charges or use live accounts without explicit authorization. Use disposable, authorized test resources.

## Working method

Create a durable programme manifest and evidence directory before implementation. Record repository SHA, package versions, environment, image digest, test command, timestamps, exit status, expected result, observed result and raw evidence for each gate. Each finding needs a minimal regression or reproducer before repair. Run original regressions as well as new tests after every material change.

Work in dependency order: normative contract if genuinely needed; Kernel/Permit and required SDK behavior; Airlock integration; packaging and documentation. Do not change contracts merely to bless an unsafe implementation. Parallelize only independent tasks and give each task a non-overlapping branch and acceptance contract. Inspect and test contributed patches before integrating them into the candidate.

Continue through every locally actionable item. If a gate needs unavailable Docker, a resource-owner account, external reviewer, secret, platform access or publication permission, mark that gate BLOCKED with exact evidence and continue other unblocked work. Missing dependencies are not a license to mock a security boundary. Checkpoint before tool/session limits, leaving a resume command and the next concrete test.

## Mandatory completion gates

### A — One coherent candidate and truthful compatibility map

Produce one exact-source and exact-artifact matrix covering Protocol, Kernel, Permit, Scan, Airlock and every advertised language/profile. Reconcile the differing standalone SDK pins in Kernel and Airlock. Distinguish wire conformance, stateless verification, replay enforcement and effect protection. Retain supported older versions' regression obligations. A schema or stateless verifier must not be advertised as an effect-protected executor.

### B — Exact authority and request identity

Show that policy evaluation, proof creation, independent verification and dispatch operate on the same validated, typed request. Normalize once before authority evaluation, or reject unsupported representations. Trace Permit's float-to-string and tuple-to-list conversion through actual adapters; add tests for 1.0 versus "1.0", boolean versus integer, tuple versus list, nested values, Unicode and large integers. Either prove an explicitly documented typed normalization reaches dispatch unchanged or repair the ambiguity. Do not label a source projection collision an execution exploit without a reproducer.

Run raw-byte negative tests for duplicate/case-variant members, malformed UTF-8, oversized/deep JSON, canonicalization labels, Unicode ordering, negative zero, invalid signatures, unknown keys, wrong target/audience/tenant/subject/action/parameters, expiry, revocation and proof replay. Use a frozen normative corpus with expected decisions and exact hashes. Run each claimed implementation; compare decisions and canonical bytes, not only aggregate test counts. Resolve or explicitly constrain safe-rejection divergences such as Rust's numeric domain. No dangerous acceptance mismatch is permitted.

### C — An externally enforced protected boundary

Prove the agent cannot obtain credentials, alter policy/keys/state, self-approve, self-reconcile, or reach protected external resources through a second path. Test raw IPv4/IPv6 sockets, DNS, proxies, nested processes, native code, git push, host/Docker sockets, mounts, symlinks, inherited environment, cwd changes, fake manifests and bridge replacement. Verify actual container settings before startup, including CPU/memory/process limits and exact mount identities. Main's missing CPU-quota validation was observed in an isolated source probe; verify the PR repair on actual supported platforms. No silent fallback to cooperative Local Mode.

Describe the trusted host/image/kernel assumptions and any remaining disk-quota limitation. Do not treat syscall denials as individually signed observations unless they are actually observed. Copied workspace outputs remain untrusted and must not be executed automatically on the host.

### D — Real effect ownership, truthful outcomes and recovery

For the supported mutation, use a trusted provider-specific consequence identity and exact target/parameter projection. The agent cannot reset identity by changing tracing headers, session, source, grant, proof or attempt ID. Do not infer semantic read-only behavior solely from GET/HEAD/OPTIONS for arbitrary endpoints.

Reserve effect ownership and applicable cumulative budget atomically in a durable store; independently claim the exact reservation at the execution boundary before credential release. Test threads, separate processes, races, restarts, store failures, stale authority, crashes before/after dispatch and response loss after provider commit. A committed effect and an ambiguous effect must not be blindly dispatched again. Test legitimate repeated business operations separately so deduplication does not destroy usefulness.

Trusted reconciliation must bind the original effect, reservation, attempt and reviewed state; conflicting or replayed reconciliation must not authorize a duplicate or refund twice. Verify actual provider state independently. HTTP success is not automatically COMMITTED; a timeout is not NOT_EXECUTED. Claim only local-host coordination unless shared-store multi-host tests actually pass. No universal exactly-once claim.

### E — Useful unchanged external-agent acceptance

Freeze an ordinary external coding-agent version, an existing real bug/task, its unchanged regression tests, the model configuration and resource budget before running. First establish that the same agent/model can solve the task in the matched baseline; retain baseline failures rather than blaming or excusing the boundary by assumption.

Under protected mode, the agent must inspect the project, modify code, run shell/Python and unchanged tests, build or compile as appropriate, and create a local git commit with a genuine fix. Require one explicitly approved GitHub mutation in an authorized disposable repository and confirm the exact external outcome. Then run the boundary attacks from that same protected environment and grant context. Do not replace the agent with a scripted answer, alter its source to satisfy the harness, relax the tests or use a canned provider response as useful-agent evidence.

Continue to the existing three-original-repository/ten-total-agent-case gate. Report every run and configuration change. All scored tasks must pass their preregistered checks; any unauthorized protected consequence fails the security gate. Cross task utility with protection: blocking everything does not pass.

### F — Installation, review and independent evidence

Make one documented Airlock entry point handle discovery, explicit review, authority diff, protected execution and evidence inspection. A proposal does not approve itself; CI trusts the base revision's approval root. New or unresolved authority remains denied. Removed authority cannot silently survive in a new grant.

Reproduce a clean candidate installation from built artifacts without sibling checkouts or editable installs. Separately verify a public-registry-only installation once the exact artifacts are publicly available and publication is authorized. Until then that release gate remains BLOCKED; Git pins and local wheels do not count as public release verification.

Supply a one-command reproduction harness, immutable manifests, raw results, receipts, trusted provider observations, redaction rules and an independent offline verifier. Report integrity, journal completeness and provider truth separately. Test tampering, removal, reordering and rollback assumptions. Arrange two independent operators on fresh supported machines; do not mark independent reproduction complete on the basis of self-authored CI or another agent rerunning the same cached workspace.

## Simplification and documentation

Keep Airlock as the product and the underlying libraries as coherent implementation boundaries. Retain Scan's independent adoption path and Kernel's independent verification. Remove genuinely redundant code only after identifying consumers, compatibility obligations and passing replacement tests. Do not remove already-separated standalone SDKs or confuse TypeScript types, clients and verifiers. Freeze unrelated Blastradius expansion, new cloud administration, new languages, speculative attestation layers and additional providers until demanded by the acceptance workflow or real users.

Rewrite public claims to match exact demonstrated versions and threat models. Distinguish cooperative mode from protected mode, source candidates from releases, proofs from reservations, transport responses from committed consequences, and test fixtures from external-agent acceptance. Remove “finished”, universal parity, complete discovery and exactly-once claims unless the corresponding evidence exists.

## Final delivery and stopping rule

Deliver the implemented candidate, reviewable changes, compatibility matrix, test matrix, failure ledger, installation/reproduction commands and evidence hashes. Classify every gate as IMPLEMENTED, VERIFIED IN THIS ENVIRONMENT, INDEPENDENTLY REPRODUCED, FAIL or BLOCKED; attach the actual supporting evidence. Give a single overall status: CANDIDATE READY, RELEASE READY, or NOT READY, with precise remaining blockers. CANDIDATE READY requires all candidate gates, including useful work and containment, to pass; RELEASE READY also requires authorized public-artifact verification. Neither may be inferred from green unit tests alone.

Do not stop merely because one patch passes or a demo looks persuasive. Stop when the measurable scope is complete, or when all remaining work genuinely requires external capabilities or authorization, after finishing every independent actionable item and preserving an exact continuation checkpoint.
