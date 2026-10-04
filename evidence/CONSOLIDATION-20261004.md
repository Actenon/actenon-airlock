# Canonical source consolidation — 2026-10-04

This update preserves PR #3's adapter and external-agent evidence, then replaces its historical source pins with the merged unified ecosystem. Historical acceptance receipts remain evidence for their original dependency set, not evidence for this new build.

- actenon-scan: `ee971b43c78ed8b58f5f7fb59382ab20ce9b8a5c`.
- actenon-protocol: `4cbd8f04e0db331b2ffd490d50c0a7aede2d35ff`.
- actenon-kernel: `5ca02e10bf329bfa090530d77301686e5995de3a` (reviewed #44 head; merge `f144f41a3fb7ab5af9910eecbb19fbfce8cc524d` has the identical source tree).
- actenon-permit: `2a429d5b2de2f0ba3ecc1c91996ae25c8d84ff61`.

Kernel now contains the full production #41 and provenance #43 histories, signed minter extensions, strict edge verification, durable replay and authoritative revocation. Permit contains #22 and #23, with the immutable grant signature boundary shared by Python and TypeScript. Go and Rust have separately merged their combined candidate histories and the same frozen Kernel vectors.

Airlock now uses Permit's `authority_payload()` rather than excluding the entire budget itself. It verifies the stored grant and checks the same signed payload against launch authority. Normal `budget.remaining` changes are accepted; altered limits/currency/scopes fail closed. Scan's public path normaliser is consumed directly. Doctor expects Protocol 1.5.0/wire 1.2.0.

This remains **0.1.0.dev0**, a source integration candidate. Dependencies are not all published; no Airlock package, release or tag is created. Source-install and development-wheel tests do not count as published fresh-install evidence.

## Remaining product acceptance

- Local filesystem/process adapters release operations to a cooperative agent; they do not establish observed execution or OS containment.
- GraphQL is not yet decomposed into bounded semantic authority. Dynamic/template resources, aiohttp, protected processes, filesystem object binding, PostgreSQL consequence execution and blast-radius rehearsal remain open work.
- The three historical external-agent traces expose real denials and usability failures. They do not establish complete legitimate workflows or the final three-agent acceptance PASS.
- The original launch-wide unsupported-kind refusal is still needed for effects without a runtime adapter. It must be removed only when the actual boundary can fail closed per effect.
- Registry-based single installation, trusted deployment approvals, exact final release graph, public-artifact consumption and the finished demo remain mandatory gates.
