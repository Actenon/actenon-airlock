# Independent Airlock boundary evaluation

This contribution repairs receipt and effect-store recovery gaps and closes unsafe header assumptions in the milestone candidate. The supported protected deployment still permits reviewed text inference and exact GitHub file creation. Its network boundary was exercised using functioning, owned transport endpoints, actual Linux containers, and the installed Scan, Permit and Kernel candidate graph.

This is independent engineering evidence, not release admission or a retrospective acceptance pass. No model selected these attacks. No paid model, production credential, package publication, deployment, tag or merge was used.

## Source and isolation

Evaluation date: 30 October 2026. Tested implementation commit: `fe6d407a0728edac92a7e9e6408bd7ddec1d10a7`. The starting Airlock revision was `341ce3a2f10d2eafa5b07e74539a36e16d3dfac2` on `feat/airlock-milestone-1`, descending from integration candidate `426bdaae9d4f854db877271177c4455b7e286631`. GitHub was refreshed before work and again before integration preparation; the milestone remained at that revision. The reviewed effect correction is `8bf8a78dbee823b6bf345f6a5469855c8671ca0b`.

A separate local clone, separate linked worktree and branch `codex/airlock-independent-security` were created. Claude's checkout, branches, worktree metadata and `.airlock` state were not edited. Every test project, database and signing key was disposable. Docker resource names use random identifiers; the image tag is `actenon-airlock-codex-assurance:20261030`. Test containers, volumes and the internal control network are removed by their harnesses.

| Dependency | Tested source commit |
| --- | --- |
| Protocol | `a2e0e08fcd24b71eb1668204ba6bed00e4c63551` |
| Kernel | `7a1ad40581ce0f984f5b1cc4292f26d350cab311` |
| Permit | `b795a37cfa927c630605172f8ecaf073bfb2aa70` |
| Scan | `16388227a55a3b5a3ec392d1c70f3940b0c291c1` |
| Go SDK | `c3d07ef535e04b4a981a921f1430c58397d0dbc4` |
| Rust SDK | `cc317fbd2cf971630451af07042bbe2d6dbea724` |

The TypeScript verifier comes from the Kernel commit above. [Source manifest](evidence/source-manifest.json), [installed packages](evidence/installed.txt) and remote branch inventories record provenance. All five repositories were inspected; only Airlock needs changes for these corrections.

## Reproduced defects and repairs

The existing 18 effect-durability tests passed before edits. Additional tests then failed on the original implementation, with provider requests counted. See [baseline effects](evidence/baseline-effects.log), [recovery negative controls](evidence/negative-recovery.log) and [header negative controls](evidence/negative-headers.log). These logs preserve failing assertions, not newly relabelled acceptance results.

| Defect | Original observed behavior | Correction and permanent control |
| --- | --- | --- |
| Invalid journal accepted at startup | Signature modification, removal of a receipt and reordering each still allowed a new loopback POST. | Reject overall journal verification failure; verify the existing chain under the append lock before extending it. `test_invalid_journal_blocks_new_consequence` |
| Crash-window ownership omitted | After one observed POST, retaining only its pre-dispatch signed receipt and losing the database allowed a second POST. | Recover the ownership reference embedded in the authorized proof, before there is an outcome receipt. `test_authorized_receipt_alone_preserves_crash_window_ownership` |
| Old attempt masks a lost owner | A genuine NOT_EXECUTED attempt remained in an older SQLite backup. Restoring it after a later dispatched attempt allowed another POST, because the effect ID still existed. | Require each journal-recorded reservation/attempt and check its recorded outcome against the store. `test_older_non_execution_attempt_cannot_hide_missing_live_owner` |
| Retry refusal erases ambiguity in reports | A second request was correctly blocked, but its DENY row caused offline evidence to stop listing the original ambiguous effect. | Outcome-less denials no longer replace provider outcome history. `test_retry_denial_does_not_erase_unresolved_provider_truth` |
| Unknown header semantics silently ignored | Stripe account, OpenAI project, precondition and idempotency headers reached the provider without a supported consequence interpretation. Method override and content encoding also passed. | Reject unsupported header contracts before dispatch; discard named SDK diagnostic headers before authority evaluation and transport. `test_unknown_consequence_headers_never_dispatch` |
| Header variation resets ownership | Changing `application/json` to `application/json; charset=utf-8` allowed the same request bytes to dispatch twice. | Generic byte-request ownership no longer varies with any header, including credentials. Exact dispatched headers remain proof-bound. Unknown or distinct header-dependent operations need a provider executor. `test_content_type_cannot_reset_ambiguous_byte_ownership` |
| Inference method override forwarded | A protected request carrying `X-HTTP-Method-Override: DELETE` reached the synthetic inference transport despite POST authority. | Reject the unsupported override before transport. `test_inference_method_override_never_reaches_provider` |

A final upgrade regression also confirmed that legacy owners must be inventoried from the database independently of the journal; the fix covers that surviving-database case. This was caught and repaired during development, not attributed to the original milestone.

The stricter recovery check also exposed an incomplete recovery record: a Kernel refusal settled an effect as NOT_EXECUTED without recording the bound reference in its final Airlock receipt. Such refusals now retain effect evidence, proof ID and their authorized parent receipt. Verified non-execution remains retryable; it cannot impersonate a lost later owner.

Existing concurrency and SIGKILL controls still exercise real processes and count real loopback provider dispatches. New grants, broker restarts, tracing identifiers and source/profile changes do not reset the supported GitHub consequence identity. The eight-process race still has exactly one provider dispatch.

## Header contract and upgrade behavior

Generic HTTP cannot establish universal provider semantics. The Local Mode broker provides a conservative hold for the same method, target, body bytes and Scan capability. It does **not** establish that two differently encoded bodies, URL aliases or distinct provider operations are the same consequence. Local Mode remains cooperative interception, not the hostile-agent execution boundary. The new checks do not promote generic HTTP into a supported Protected Mode consequence contract.

Protected Mode continues to reject arbitrary HTTP actions. Its supported contracts are reviewed text inference and the exact reviewed GitHub Contents creation executor. The latter replaces caller headers with fixed trusted provider headers and derives identity from the reviewed repository/path/branch consequence. Broader tenant, account, precondition and idempotency semantics require a reviewed provider executor rather than additions justified merely by a header's name.

Two existing development tests expected Content-Type or credential changes to create distinct generic effects. They now expect conservative refusal. These were implementation regressions, not frozen real-model acceptance gates. Distinct body requests and separately reviewed GitHub paths still have positive controls.

**Upgrade must fail closed.** Existing held header-dependent effects from the prior identity scheme cannot be silently forgotten. Startup detects their old nonempty header contribution and refuses execution, including when only the database survives. The inventory opens the pinned Permit database read-only; it does not modify its reservation schema or state. Historical NOT_EXECUTED records with no corresponding bound terminal receipt can also require trusted recovery. No automatic migration/reset is supplied here. See [recovery operations](../../docs/operations.md). Deployments with such history must preserve the old key, database, journal and independent checkpoint and prepare an authenticated migration before upgrading. Fresh test projects and the GitHub semantic descriptor do not need an identity conversion. Do not delete state or rotate keys to bypass the check.

## Actual Linux containment

The independent test creates a disposable Docker network marked internal, with IPv4 and IPv6, and an owned sink that logs received traffic. Network-enabled controls using the same image must deliver each probe before the protected run is attempted. A missing dependency or unreachable sink fails the test.

| Probe | Working control | Protected result and observation |
| --- | --- | --- |
| IPv4 TCP | Sink received `ipv4` | No additional sink event |
| IPv6 TCP | Sink received `ipv6` | No additional sink event |
| DNS resolution | Docker-resolved owned hostname delivered `dns` | No connection reached the sink |
| Native libc socket/connect/send | Sink received `native` | No additional sink event |
| Raw IPv4 UDP socket | Sink received `raw-udp` | No additional sink event |
| Explicit HTTP proxy | Owned proxy received request | No additional sink event |
| Nested subprocesses | Grandchild delivered `nested` | No additional sink event |

The agent uses the actual `launch_protected` boundary, not a mocked Docker interface. Container inspection verifies `network=none`, dropped capabilities, read-only control mounts, private IPC and the prescribed user. Additional probes verify Docker socket absence, host-file absence, sanitized environment and `/proc/1/environ`, rejection of a control-file write through a symlink, and inability to replace the bridge socket. Forged approval, forged reconciliation and unsupported HTTP RPCs are denied. These filesystem assertions establish only the tested paths and planted values, not exhaustive credential discovery.

The independent sink logs are identical before and after the protected probes. The same protected run then successfully obtains a response from a **real loopback HTTP inference fixture through the trusted supervisor**, with the approved output bound inserted. This is a working approved external operation with actual transport; the response is synthetic and no LLM ran. Existing Docker GitHub and engineering-workflow controls also run, using their explicitly synthetic provider fixtures.

See [transport observations](evidence/boundary/transport-observations.json), [inspected boundary](evidence/boundary/boundary.json), [run result](evidence/boundary/result.json) and the public signed receipts alongside them. The new CI step runs this independent test without changing the historical gate definitions.

## Exact authority and canonicalization

New adversarial tests run the actual Scan vocabulary, signed Permit scopes, finite GitHub grant, Protocol action/proof representation, Kernel effect claim and host provider adapter. Changed boolean/integer/string values, nested values, floats, large integers and duplicate JSON members cannot become the reviewed GitHub action. Changed target, capability or body hash after policy approval is rejected at the Kernel edge before provider I/O. Reordered JSON object members and whitespace still map to one exact reviewed GitHub consequence. Every malformed creation case has a valid creation positive control using the same broker and provider fixture.

The candidate's existing SDK conformance script passed in Python, TypeScript, Go and Rust against its hash-locked vectors. A separately frozen 32-case raw JSON corpus extends the SDK corpus with nested typed authority, escaped duplicate members, negative floating zero, Unicode ordering and a negative arbitrary-precision integer. Both installed Python Protocol and Python Kernel consume exactly those raw bytes; the TypeScript, Go and Rust runs use the same frozen file. Raw and canonical SHA-256 values are checked.

All supported acceptances matched canonical bytes. TypeScript safely refused four large-integer cases; Rust safely refused four cases including negative zero and out-of-range integers. These are explicit representation limitations, not acceptance parity. Neither Unicode normalization nor unsafe numeric coercion was introduced to make tests pass. The corpus checks parsing/canonicalization; whole-proof authority, audience, expiry, revocation, replay and mutation are separately exercised by Kernel conformance/security and Airlock integration tests.

[Python corpus results](evidence/canonical-python.log), [TypeScript per case](evidence/canonical-typescript.json), [Go per case](evidence/canonical-go.json), [Rust per case](evidence/canonical-rust.json), [SDK conformance](evidence/sdk-conformance.log).

## Evidence and recovery limits

1. **Cryptographic integrity:** a valid signature and chain establish integrity of retained signed records relative to a trusted key. They do not prove execution success. Corrupt or reordered retained journals now prevent startup; malformed/incomplete appends prevent extension.
2. **Completeness:** a valid prefix can still be truncated or rolled back. An independently preserved, recent signed checkpoint can detect truncation or divergence offline. The current runtime does not consult an external checkpoint service. A checkpoint stored beside attacker-rewritable evidence is not independent, and an old journal with its matching old checkpoint remains consistent.
3. **Provider state:** runtime HTTP success remains ambiguous for generic mutations. A signed authorized-observer reconciliation is an attestation whose reliability depends on the observer and its provider observations; signing alone cannot make the assertion true. Synthetic GitHub observations are test inputs, not evidence about live GitHub.

The limitation control `test_total_local_history_loss_is_not_claimed_to_be_detectable` deliberately deletes both trusted local ownership histories in a disposable project. A second dispatch is then possible. Its independently retained checkpoint rejects the rewritten journal offline. That result is explicitly recorded as a residual assumption, not a containment pass. Retaining the database while losing the journal still blocks the duplicate effect.

Operator evidence verification, expiry, key binding, conflicts and concurrent settlement retain their existing regressions. Unknown or conflicting store/journal history is held for trusted recovery; it is never converted into inferred non-execution. Receipt append now verifies the complete retained chain under its lock. This adds work linear in journal length per append; long-lived journal performance has not been benchmarked here. Optimizing it must preserve independent completeness and tamper checks.

The current check is not a defense against an attacker who can rewrite all trusted host state or compromise the host signing keys.

## Resource owned Kernel enforcement

The candidate Kernel's security suite and pinned verifier conformance were exercised separately. Resource-owned enforcement can gate specific API callbacks where the resource owner actually requires the verified proof, replay/claim state and exact action. Tests cover alternative entrypoints, changed/unowned effect references and races before the callback. This provides no blanket protection for unrelated public websites or unintegrated operations. Airlock's managed container and Kernel's resource-owned enforcement remain distinct deployment boundaries.

The additional Kernel run passed 333 tests and 43 subtests, with 14 explicitly skipped tests: 12 require the absent optional `mcp` package, and two target an unimplemented legacy reconciliation module. None of these skips counts as a denial or containment result. It is not claimed as a complete independent test of every optional Kernel feature. The Airlock candidate graph is unchanged.

## Threat model inputs

[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) motivates treating tool misuse, privilege abuse, unexpected execution and untrusted coordination as boundary threats. Here those concerns are translated into exact external authority, independent execution mediation and observed consequence tests; this is not an OWASP certification.

[Anthropic's September 2026 alignment assessment](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents) describes cybersecurity evaluations that unintentionally exposed models to real external systems. That evidence motivates verifying actual network isolation rather than trusting a simulated-environment instruction or a model's account of its behavior. The attacks in this contribution were selected by the test harness and executed by ordinary code inside Airlock, not autonomously chosen by an AI model.

## Final validation

Implementation `fe6d407a0728edac92a7e9e6408bd7ddec1d10a7`: **593 Airlock tests passed, zero skipped**, with all three actual Docker tests enabled. Ruff lint and format checks passed. Source distribution and wheel builds passed, and the built wheel passed `airlock doctor --json` in a separate clean environment resolving the exact candidate dependency graph. No admission verdict is inferred from these results.

[Full test log](evidence/full-tests-final.log), [JUnit results](evidence/full-results.xml), [lint](evidence/lint.log), [build](evidence/build.log), [installed wheel diagnostics](evidence/wheel-doctor.json). The separate Kernel security and cross-language runs are scoped above. Evidence file hashes are recorded in `evidence/SHA256SUMS.json`; this manifest supports reproducibility, not independent authentication of a release gate.

## Reproduction and integration

Install `.[test]` in a fresh Python 3.12 environment at this branch; its candidate dependency pins must resolve without overrides. Build `containers/Dockerfile.compute` using a unique image tag. Then run:

```sh
AIRLOCK_TEST_PROTECTED_IMAGE=actenon-airlock-codex-assurance:20261030 \
AIRLOCK_INDEPENDENT_EVIDENCE=/absolute/disposable/evidence \
python -m pytest -q --junitxml=full-results.xml
ruff check src tests scripts
ruff format --check src tests scripts
python -m build
```

The independent container test owns and removes its control network and endpoint. Do not run against production credentials. Its positive inference provider is local and free.

For cross-language replication, use the Kernel and SDK commits in the source manifest. First run Kernel's `scripts/verify_sdk_conformance.sh` with an isolated `ACTENON_SDK_CACHE` and the candidate Python environment. Then copy `tests/fixtures/independent/canonical.json` to `fixtures/protocol_canonicalisation/raw-corpus.json` in **disposable** Go and Rust SDK checkouts. Run Go's `TestProtocolRawCanonicalCorpus` and Rust's `frozen_raw_canonical_corpus`, with `ACTENON_PARITY_RESULTS` pointing to separate output files. Run `scripts/independent-canonical.mjs` using the Kernel TypeScript SDK's `tsx` loader and pass absolute SDK/corpus paths. Airlock's `test_independent_canonical.py` checks both installed Python implementations.

Review this branch as a draft PR against `feat/airlock-milestone-1`. Integrate through ordinary review after checking any newer Claude changes and the explicit upgrade constraint. Do not rebase or overwrite Claude's branch. The release-admission implementation, owner settings, frozen real-model failures and A–F/G1–G40 definitions are unchanged. These results neither authorize release nor replace authenticated release evidence.
