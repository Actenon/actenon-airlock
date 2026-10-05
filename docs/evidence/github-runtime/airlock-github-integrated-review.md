# Protected GitHub slice: focused integration review

Scope: the local candidate in `work/actenon-airlock-github`, with Protocol `8e5bc9e342f694767508bae9a392749c6a8df2cc`, Kernel `66052b20941f908634c9fbac24f1ae7cead78e46`, Permit tested source `fd120449e74bb8050cbf58d4b3488eef770239fc` / byte-identical packaged follow-up `1443e36d7a6224da055b2c3011ec248f4609d1eb`, and Scan `ee971b43c78ed8b58f5f7fb59382ab20ce9b8a5c`.

The review found no remaining concrete authority bypass in the supported in-process GitHub creation path. This is a focused code and fixture-transport assessment, not proof of arbitrary-provider safety, a live GitHub result, or Linux containment.

## Observed authority and execution path

- Protected model traffic has a separate exact transport scope. Each GitHub create profile receives its own signed Permit finite-effect grant, one call, with its effect ID derived from the reviewed provider projection and Scan's capability vocabulary.
- Kernel's independent descriptor callback reconstructs the GitHub semantic identity from the signed exact Action Intent. Permit's atomic edge claim occurs before credential materialization or host preflight GETs.
- The provider adapter canonicalizes and binds the actual PUT body; agent-selected headers do not change the provider semantic identity. Repo identity, reviewed parent, and file absence are validated before mutation. The profile explicitly requires exclusive-writer operation because GitHub Contents does not provide the required branch compare-and-swap guarantee.
- A successful PUT response remains AMBIGUOUS. An observed preflight rejection, before any PUT, records NOT_EXECUTED. A timeout after dispatch remains held with no retry.
- Seven selected installed Permit/Kernel integration tests passed for claim ordering, changed-intent denial, model-grant separation, restart duplicate suppression, and truthful preflight denial. Evidence: `airlock-github-runtime-review.log`.

## Review finding resolved

The initial authorized receipt lacked the original reviewed GitHub profile. Reconstructing from the current approval would be unsafe for the original expected parent and exclusive-writer assumption, which intentionally are not part of the duplicate-effect key. The runtime now signs `github_profile` into the authorized receipt. The observer refuses missing or mismatched historical snapshots and recomputes the exact request, action hash, descriptor hash, namespace, and effect ID against the bound ledger reference before reading credentials.

## Host observation implementation and evidence

`github_observer.observe_github` verifies the operator key against the current signed approval, reads a consistent held attempt, and obtains only fixed host-derived GET URLs. It observes repository immutable IDs, the branch commit anchored to the original parent, and exact bytes at the validated immutable commit SHA. A signed 201 acknowledgement, when present, must agree with readback. The pure existing provider contract validates the result.

The helper never PUTs, retries, refunds, or settles. COMMITTED produces an operator-signed envelope for the existing reconciliation path. Missing, 404, conflicting, redirected, oversized, or timed-out readback stays AMBIGUOUS without an envelope or ledger change. The successful result explicitly carries `causal_attribution: not_proven`; matching state under the exclusive-writer assumption does not independently identify which process caused it.

Evidence files remain owner-only under `.airlock/local`. They preserve the reconciliation request snapshot, original profile, exact body and provider response hashes, and bounded raw responses. They can contain private code or provider user metadata and are not public exports. HTTP headers and exception text are excluded. Detected active credentials, including decoded Contents data, are replaced by hash-only records. No automatic upload exists.

Twenty-two observer tests pass with actual installed grants, proofs, ledger and receipt signatures and fixture-only HTTP transport: `github-observer.xml` and `github-observer.log`. They include exact/lost-ACK readback, no observer-side state mutation, explicit reconciliation and replay, denial after commit, negative readback, operator revocation/order, original-vs-current profile custody, signed request/receipt/envelope mutations, and credential redaction. Lint passes for both new files.

## Remaining acceptance boundaries

No claim is made here for actual disposable GitHub mutation, useful external-agent completion, Linux containment, production or public-registry installation, exclusive-writer enforcement by GitHub, or two outside operators. Those remain separate gates. Permit bearer-token/control-plane ingress remains outside this in-process protected profile as previously recorded in `permit-integrated-review.md`; the known token parsing availability issues were not silently treated as fixed.
