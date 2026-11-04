# V4.4 image compatibility and contract observatory

## Established failure

Starting remote PR #23 was verified as draft at `208163b8e69058ae2906081893af5db072b45b2a`. Offline verification of the original V4.3 journal/public key/checkpoint verifies all five receipts and an ANCHORED five-entry checkpoint. Receipts 2 and 4 record `response-schema`, stage `response-object`, event zero `response.created`, and the public identifier `image`. The two AMBIGUOUS holds are **681,765 + 694,570 = 1,376,335 micro-USD**. Agent exit is 1; visible tests are 2 pass/1 fail and hidden tests 3 pass/1 fail. The evaluator reports runner exit 1 and refusal of the next reservation under the $2 bound. These are reservations, not verified provider bills.

High confidence: the old allowlist rejected an actually present `image` property. Unknown: its value and whether the rest of either live stream would pass this repair. No historical response bodies, prompts, reasoning, agent logs or credentials were inspected. Historical evidence and freezes are unchanged. `live-evidence.json` records safe extraction and original-file hashes; `live-verification.json` records signature/checkpoint verification.

## Reproduction and narrow repair

Regression-only commit `9be175e` precedes production edits: **9 expected failures / 63 passing negative controls**. The failing cases cover complete SSE/JSON responses, optional snapshot omissions and real broker settlement. The full fixture carries eight authored Codex-style function/custom definitions, direct-only defaults, default penalties, zero hosted usage, nullable optional metadata, cache-write zero, image policy, complete output and bounded usage. It approximates the reviewed contract, not unavailable live bodies.

The [official response schema](https://developers.openai.com/api/reference/resources/responses/methods/retrieve) makes `image` optional, with required `context_compression` equal to `enabled` or `disabled`. Neither object nor member is documented nullable. The [request schema](https://developers.openai.com/api/reference/resources/responses/methods/create) additionally offers `auto`; that request setting is not an effective response value. The pinned SDK 2.54.0 does not declare `image`. No source located establishes a GPT-5.5-specific guarantee for when this metadata appears or what its value will be.

Commit `28fc303` admits only omission or the exact one-member response object with those two enum values. Null, empty/malformed objects, missing members, `auto`, unknown members and conflicting effective policies across present snapshots fail confirmation. An omitted snapshot is no echo; the first present policy remains binding through later omissions. The JSON path receives the same shape validation.

This is effective input-context policy metadata. It is distinct from image input authority, generated image output, hosted image-generation execution and hosted financial usage. This text-only request profile gains none of those capabilities. Outbound validation is unchanged; image inputs and the request-level `image` property remain refused. Hosted outputs/tools remain forbidden; nonzero hosted usage and cache-write categories remain unsupported. Model identity, output consistency, terminal completion, typed/bounded usage, reviewed pricing, Permit/Kernel, replay, signed receipts and credential isolation are unchanged. HTTP 200 or a successful diagnostic probe cannot settle inference.

## Complete schema comparison

`COMPATIBILITY_MATRIX.md` and versioned `compatibility-matrix.json` cover the **42-property union** of the Airlock allowlist, exact installed SDK declarations and current reference. `build_matrix.py` independently checks inventory coverage and records SDK/document hashes. It never generates production permissions. Fields are classified by actual acceptance and relevance to identity, completion, provider state, authority, billing, generation or description.

The matrix deliberately exposes inherited opaque echoes: accepting a property name does not imply every value has semantic validation. Examples include stored-prompt metadata, service tier, retention and several generation echoes. Their values do not alter outbound authority or accounting prices, but their provider semantics are not comprehensively enforced. This change does not silently expand or tighten those existing contracts. `store`/`background` retain the old equality behavior that also admits numeric zero. These limitations deserve separate review before additional request features are supported.

`prompt_cache_diagnostics` stays unsupported, including explicit null. The reference describes tagged cache-hit/miss/comparison-unavailable results, not billing usage. The [diagnostics guide](https://developers.openai.com/api/docs/guides/prompt-caching/diagnostics) ties them to an explicitly supplied comparison response; current cache options concern GPT-5.6 and later. This GPT-5.5 request cannot supply that option. A populated diagnostic is inconsistent with the reviewed request assumptions, not grounds for silently enabling a comparison reference. `output_text` is SDK-only convenience, also unsupported on the wire; both names are fixed public diagnostic identifiers.

Live provenance is kept distinct: V4 did not retain a field-name set (the three nullable fields were SDK hypotheses); V4.1 signed hashes identify penalties and tool_usage but not values; V4.2 identifies the tools validation stage but not offending nested members; V4.3 identifies image but not its value.

## Independent bounded observatory

Regression-only commit `1c4ecf7` preserves **30 expected missing-feature failures**. `a49e38f` implements a separate read-only module. The authoritative observer completes its immutable verdict first. Only then does the wrapper attach `contract_observatory` to the signed diagnostic record. The analyser receives bytes and the approved request, not a writable verdict or accounting object. It never calls a provider, dispatches a tool, changes a request, retries, settles a hold or provides an authoritative usage value. The wrapper changes only the diagnostics dataclass field. Analyser exceptions, including import failures (`ee1f48d`), yield a fixed unavailable marker without changing confirmation, decline or usage.

Independent probes inspect top-level schema, individual restricted fields, tool inventory and per-tool identity/definitions, both hosted-usage categories and counters, output items, model/response identity, token usage, framing/sequence and missing terminal completion. Diagnostic-only projections let stream/output checks proceed past unrelated metadata failures. These projections and probe results never enter the authoritative path. Namespace strictness remains scoped; reordered valid echoes do not create false diagnostics. Multiple defects are reported in one summary; coverage is bounded rather than a claim to enumerate every possible defect in arbitrary input.

Each issue has a fixed stage/reason, a bounded path of public identifiers/list indices, optional fixed tool-detail reason, and up to four public field identifiers or JSON-name SHA-256 hashes. No property values, descriptions, private schemas, arguments, instructions, reasoning, encrypted material, errors or credentials are copied. Hashes are correlation identifiers, **not encryption**: predictable names can be dictionary-matched. The authoritative diagnostic retains its existing separate bounds.

Added inspection limits: **4 MiB input, 256 events, 4,096 lines, nesting 24, 8,192 structural tokens, 512 semantic probes, 32 issues, path depth 10, four field identifiers per issue and 16,384 serialized report bytes**. A lexical guard runs before JSON allocation; per-frame guards prevent malformed prior frames from evading depth checks. Byte/token/probe budgets bound parsing, comparison and walk work. Reports explicitly mark truncation. This is deterministic work bounding, not an operating-system time quota. An exhausted diagnostic budget cannot downgrade a valid response or upgrade an invalid one. The existing authoritative 4 MiB input/stream rules are unchanged.

Tests cover simultaneous unknown field/changed tool schema, valid image/invalid usage, invalid image/nonzero hosted usage, incomplete stream/hosted output, invalid strictness/provider state, conflicting snapshots/changed identities, unknown billed categories and broken sequence/missing terminal. Fault injection proves verdict/usage independence; secret injection verifies receipts and captured console output contain no plaintext secrets. Altering a diagnostic invalidates its signed journal. Tests also cover depth, node, event, issue, byte and work limits, malformed/nonfinite JSON and valid namespace/reordering cases.

## Accounting evidence

`replay_accounting.py` uses actual broker/Permit/Kernel dispatch with an HTTP mock. Fifteen independently checkpointed replay journals are in `signed-replay/`; every signature/checkpoint verifies ANCHORED. Invalid image, hosted activity and an unknown billing category are each exercised alone as well as in combinations.

| Synthetic case | Initial reservation | After response | Next call / final exposure |
|---|---:|---:|---|
| Evaluated V4.3 observer, valid image metadata | 509,795 | 509,795 held | Refused / 509,795 |
| Repaired enabled or disabled policy | 509,795 | 1,055 validated estimate | Confirmed / 2,110 |
| Partial stream or any of eight multi-defect variants | 509,795 | 509,795 held | Replay and continuation refused / 509,795 |

The signed test bound is **700,000 micro-USD**. The valid continuation reserves **509,925** before settlement. Each validated estimate is 90 ordinary input + 10 cached input + 20 output tokens at the existing reviewed schedule = **1,055 micro-USD**. Unsupported hosted usage is not priced at zero or offset by valid base usage. Diagnostic findings never release exposure. These fixtures incur no provider bill and prove no autonomous live completion or external business effect.

## Source identity discrepancy

> **Correction (2026-11-04):** the origin of 4e724a87 has since been established: no tool ever computed it. It first appears in model-authored evaluator text and was copied into the V4.3 prompt. See `review-2026-11-04/REVIEW.md` §4 and `review-2026-11-04/digest-provenance.json`. The text below is preserved as originally delivered.

The frozen runner hashes sorted package-relative UTF-8 paths, NUL, then raw file bytes under `src/actenon_airlock`, excluding `__pycache__`. Reconstructing those bytes directly from Git objects at `208163b8…` produces **6e141812c3ca5194eafaed2f234a9c41a51b88d344354e4dfd6220695c243a6e**, exactly matching the frozen live result. `historical-source-identity.json` records all 28 source files, blob identities, byte counts and SHA-256 values.

The supplied pre-flight digest **4e724a87ad908baebff0e81c19b027ca54bfbfa3224b75aa54d5807ee1d72cf5** cannot be reproduced. The retained Gemini report now contains the later 6e141812 value; a search of the specified retained evidence/report directories found no occurrence of 4e724a87. The independent test and manifest builder do not supply its original algorithm/file inventory (the builder hardcodes 6e141812). Common alternate path scopes and byte/hash concatenations did not recover it. The owner confirms the earlier report was edited and its hashing procedure was never recorded. Whether it came from a different algorithm, scope, worktree or transcription is **unknown**; there is no basis to claim source drift or tampering. This historical discrepancy is documented, not falsely resolved.

`scripts/source_identity.py` supplies an independent, import-free Git-object reconstruction and checks exact working-source inventory/bytes. Drift, extra/missing files and symlinks are tested; bytecode exclusion matches the runner. The new freeze must match this independently reproduced source identity. The historical evaluator claim remains lower-confidence provenance; the new candidate does not depend on it.

## Validation and remaining blockers

Final results and exact dependency/image identities are in `validation.json`; the delivered CI record identifies the exact final review head. Local checks include full Airlock with actual Docker, complete Responses regressions, unchanged Codex/Claude execution, broker authority/accounting/replay, credential isolation, Permit/Kernel boundaries and receipt/checkpoint signatures. Both scripted malicious-hook controls use synthetic inference and retain original assertions. Lint/format, wheel/sdist build and a clean wheel installation/doctor are included.

- **1,970 full Airlock passes**, zero failures/errors/skips with Docker 29.9.2. All six unchanged-Codex and nine Claude Code container cases pass, including actual CLI-derived tool echoes carrying image policy.
- **1,021 focused Responses passes**: all existing suites, 72 new image/full-contract cases and 37 observatory cases. Six additional source-identity tests pass in the full suite.
- Permit: **913 passed / 3 skips**, comprising two absent cloud-checkout integrations and the explicitly disabled live-model test/probe (`SKIP_LLM_TESTS=1`).
- Kernel: **978 passed + 323 subtests**; all four environment-dependent cases subsequently pass with constrained installation and real PostgreSQL 16. Two pre-existing Phase 4B reconciliation placeholders remain skipped. Conformance: **35 passed + 63 subtests**.
- Both final scripted malicious-hook controls: agent/runner exit **0**, **3 visible + 4 hidden passes**, four confirmed responses and **4,220 micro-USD** estimated accounting each; signed journals/checkpoints verify. Baseline has two synthetic-canary deliveries; protected has zero after a successful positive control. Harness hook hashes remain unchanged; the generic modification flag includes harness-planted files.
- Lint, format, wheel/sdist, clean wheel environment and doctor pass. The standalone official-binary version probe emits its existing stale-directory cleanup warning; real execution tests pass.

All final checks pass with the disclosed dependency skips. Earlier expected failing reproductions are preserved. During development, two additional diagnostic tests initially failed (missing identity detail and an invalid synthetic namespace); the detail was added and the fixture corrected to the approved namespace before final verification. The first full run passed 1,957 cases, the intermediate run 1,966; the final repeat covers the completed source and all 1,970 cases.

Python 3.12.13 / OpenAI SDK 2.54.0 and all pinned dependencies remain unchanged. Codex is the official **0.166.0** binary (`f2e6c980c937e734644bed1b4a9a018d3e63a0ccbe71aafc85c86a8c6e4b462a`) in immutable image `sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269`. Outbound requests, broker, Permit/Kernel, acceptance runner, task/hidden tests, lockfile and owner-accepted release bar are unchanged.

Synthetic validation establishes compatibility for the reviewed subset, not the unknown live image values, complete live stream behavior, actual billing, autonomous task success or release readiness. Unsupported hosted operations, provider state, additional billing categories, image inputs/generated outputs, undocumented image forms, unrequested cache diagnostics, tool-schema rewrites, flattened inline inventories and unknown extensions remain conservative refusals. The observatory may truncate and cannot guarantee diagnosis of every defect after malformed parsing or a limit.

PR #23 remains draft. No billable inference, real GitHub consequence, merge, tag or publication occurred. A fresh one-run freeze is prepared only after non-billable checks and exact-head CI pass; owner approval, independently enforced cumulative exposure and a fresh supervisor-only credential remain required. See `LIVE_DIAGNOSTIC.md`. Existing release gates remain unchanged.
