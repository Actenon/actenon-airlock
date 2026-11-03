# V4.3 echoed tool-contract repair

## Established failure and limits

The verified starting remote PR #23 head was `9d1edf8172fbc5e3b3ea05293e94f2a1dc166343`, the V4.2 evaluated candidate. All five receipts and the five-entry checkpoint in `/Users/ross/src/actenon-audit/live-codex/1-baseline-v4-2/` verify offline. Receipts 2 and 4 report `response-tools` at event zero, `response.created`, with AMBIGUOUS reservations **681,765 + 697,605 = 1,379,370 micro-USD**. The result records agent exit 1, two visible passes/one failure and three hidden passes/one failure. The next request was refused under the approved bound. These reservations are not settled provider bills.

**High confidence:** validation reached `_response()` and its call to the outbound `tools()` validator, which rejected a returned tool definition. Its exception was reduced to the single `response-tools` reason. **Not established:** which nested field, value, tool identity, schema or format caused the historical rejection. No nested inventory is present in that diagnostic. The documented extra fields below are plausible explanations, not recovered live contents. No credentials, prompts, reasoning, private response bodies or agent logs were inspected. Original V4/V4.1/V4.2 evidence is untouched. `live-evidence.json` contains a safe extraction and original-file hashes; `live-verification.json` records anchored integrity.

## Independently demonstrated defects

The old implementation uses `tools()` both to authorize outbound definitions and to validate inbound echoes. A documented direct-only echo containing default fields is therefore rejected as an unsupported local-tool field. Separately, it accepts changed schemas or an extra tool with a name in `LOCAL_TOOLS`, because it does not compare returned definitions with the request.

Regression-only commit **`43d6367`** precedes production edits: **134 expected failures / 38 passes**. This includes positive compatibility failures, negative parity failures and absent diagnostics; not every failure is a positive case. The broker reproduction (`before-broker.json`) uses an authored eight-tool inventory and actual Scan/Permit/Kernel/broker dispatch through an HTTP mock. Event zero fails with `response-tools`; **509,795 micro-USD** remain held; an unresolved retry and the subsequent legitimate call are refused under a **700,000-micro-USD** test bound. One dispatch occurs and the journal verifies. These fixtures are synthetic and do not claim to reproduce discarded historical values.

## Exact contract review

OpenAI SDK **2.54.0** declares `allowed_callers`, `defer_loading` and function `output_schema`; it does not declare `async` in these tool models. `schema-review.json` records exact model field inventories and source-file/document hashes. The SDK is evidence, not a permission generator.

The [Responses reference](https://developers.openai.com/api/reference/resources/responses/methods/create) defines optional invocation contexts, deferred-loading controls, nullable function output schema, and an optional boolean async flag. The [programmatic calling guide](https://developers.openai.com/api/docs/guides/tools-programmatic-tool-calling) identifies omission or `["direct"]` as direct invocation; programmatic calling additionally requires a hosted tool and explicit caller context. The [async guide](https://developers.openai.com/api/docs/guides/async-tool-calling) explains that true lets generation continue before a client tool returns. It does not move client execution to OpenAI.

| Echo field | Supported normalization | Conservative refusal |
|---|---|---|
| `allowed_callers` | Absent, null (SDK nullable unset representation), or exactly `["direct"]`. Outbound cannot set this field. | Empty/duplicate lists, any non-direct mode, wrong types. |
| `defer_loading` | Absent, null (pinned SDK unset representation), or exact boolean false. | True or other types; no discovery/tool-search authority. |
| `async` | Absent or exact boolean false. | True and all other types, including explicit null, which the current reference does not document as nullable. |
| Function `output_schema` | Absent or null only. | Every populated value, including `{}`. Outbound cannot authorize this field, so no populated equivalent is supported. |
| Function `parameters` | Exact canonical JSON equality with the authorized request. | Missing/null/non-object schemas, added/removed/changed nested members; no unrestricted provider schema rewriting. |
| Function `strict` | Explicit request boolean must match exactly. If omitted in the request, absent/null or boolean resolution is supported only with unchanged parameters. | Removing/changing explicit strictness, wrong types, or any accompanying schema change. |
| Custom `format` | Exact reviewed grammar; for an omitted request format, absent/null or `{"type":"text"}` is the unconstrained-text default. | Grammar/syntax changes, unknown nested fields, changed text/grammar mode. |
| `description` | Exact text; absent/null/empty are equivalent only when the approved description is empty/unset. | Changed nonempty descriptions or wrong types. No description is logged. |
| Namespace | Same name/scope, same child inventory; only the four existing namespace properties. | Flattening, renaming, nesting another namespace or adding new controls. |

The [function-calling guide](https://developers.openai.com/api/docs/guides/function-calling) permits omitted strictness to resolve to strict mode or fall back. This repair supports the resolved boolean with an identical schema; it does **not** attempt to prove arbitrary JSON Schema rewrites equivalent. Dictionary member order is immaterial; schema arrays remain exact. Unconstrained custom text is the documented default.

`additional_tools` input items remain bound to their original ordered input positions. As the [tool-search guide](https://developers.openai.com/api/docs/guides/tools-tool-search) explains, position affects availability. The response's top-level `tools` is compared to the request's top-level `tools`; inline declarations are not silently moved into that echo or used to justify additions. This conservative choice may reject a provider that flattens those inventories; no such normalization is established by the historical evidence.

## Authority comparison and implementation

Production commit **`419f511`** adds an independently defined inbound validator in `responses_inference.py`; outbound `tools()` and `check_request()` are unchanged. The broker already passes the exact canonical dispatched request to the observer. That request, rather than `LOCAL_TOOLS` membership, is the comparison source.

For every creation/progress/terminal snapshot and JSON response containing `tools`, the validator checks the schema/defaults, unique identities, count, type, namespace and normalized definition against the authorized request. Reordering unique definitions within a scope is allowed because calls identify tools by name/scope rather than list offset. The outbound order and signed request fingerprint are not rewritten; streamed output-item ordering remains enforced separately. Duplicate identities, including ambiguous duplicates in the approved inventory, fail confirmation. An omitted `tools` property is no echo; explicit `[]` must match an empty request inventory, and null is invalid. Absence cannot create a new authority grant.

A further stream review reproduced four cases where an omitted request strictness resolved inconsistently across snapshots (regression commit `d3b2d85`). Follow-up production commit **`38c5c93133d362a0b295a2e5660645a2dd2575a1`** remembers boolean resolution by namespace/name across one response, including snapshots with no echo, and refuses later contradictions. A late first resolution and reordered inventories remain valid. The state resets for the next inference.

No inference settlement follows merely from HTTP 200 or a valid echo. Model/response identity, complete SSE framing, terminal completion, output consistency and typed/bounded usage are still required. Local call validation, consequence authorization, Permit/Kernel proofs, financial formulas, replay ownership, credentials and provider-hosted-tool prohibitions are unchanged. Responses echoes are never forwarded as tool grants or used to invoke effects. Other provider observers are untouched.

## Safe diagnostics

The signed observation retains `rejection_reason: response-tools`, adds stage `response-tool-echo`, a fixed `tool_rejection_reason`, fixed `rejected_field`, and a bounded-depth numeric tool path. Reasons distinguish unsupported field/type, incorrect field type, caller mode, deferred loading, async execution, output schema, identity, duplicate identity, count and definition mismatch.

Unknown property names use at most 16 fixed public identifiers or JSON-name SHA-256 hashes, with count/truncation indicators. Schema contents, descriptions, grammar contents, arguments, prompt text, credentials and values are never copied. Schema differences identify only `parameters`; they do not reveal nested private keys. Tests inject secret names/values at tool, namespace, format and parameter-schema levels, verify absence from receipts/console, and show that diagnostic tampering invalidates signatures.

## Accounting and verification

`replay_accounting.py` compares the exact old observer with the repair through the real broker and synthetic transport:

| Observer / echo | Initial reservation | After first response | Second call | Total held/accounted |
|---|---:|---:|---|---:|
| Old / documented defaults | 509,795 | 509,795 held | Refused | 509,795 |
| Repair / approved defaults | 509,795 | 1,055 validated estimate | Confirmed | 2,110 |
| Repair / changed parameters | 509,795 | 509,795 held | Refused | 509,795 |
| Repair / programmatic caller | 509,795 | 509,795 held | Refused | 509,795 |
| Repair / partial stream | 509,795 | 509,795 held | Refused | 509,795 |

The valid second request reserves **509,925 micro-USD** before settlement. The unchanged reviewed-price estimate per completion is 90 ordinary input + 10 cached input + 20 output tokens = **1,055 micro-USD**. Tests also cover additions, changed custom format, defer/async/output-schema expansion, invalid usage and replay attempts with changed trace/cache metadata. Every accounting replay journal verifies against an anchored signed checkpoint. `signed-replay/` preserves journals, public keys, checkpoints and independent verification results, including an unknown-property secret-injection case. No private signing key is exported. Response confirmation is a validated protocol outcome; usage is an accounting estimate; neither is a final bill or verified external business consequence. No paid inference or real GitHub consequence was executed.

The final 192 new tests plus existing Responses suites pass **912 cases**. The unchanged official Codex test also synthesizes default echoes from the CLI's actual outbound definitions over four execution turns; it includes function/custom tools and reordered inventories while retaining prior assertions. Full-suite results, actual skips, image/dependency identities and both malicious-hook control outcomes are recorded in `validation.json`. The delivery and PR record exact-head CI after the evidence-only commit.

No synthetic result proves that V4.2's discarded fields/values fit this supported subset, that no later validator would reject that live stream, or that real autonomous task completion succeeds. SDK-default serialization, schema rewriting, flattened inline inventories, undocumented async nulls and new extensions remain possible compatibility limits. The next one-run baseline requires a new exact-head freeze and separate owner authorization; see `LIVE_DIAGNOSTIC.md`. The draft PR and owner-accepted release bar remain unchanged.

Final local verification:

- **912 focused Responses passes**, including **192 new tool-echo cases** and every V4.2 compatibility case.
- **1,855 full Airlock passes**, zero failures/errors/skips, genuine Docker 29.9.2. All six unchanged-Codex and nine Claude Code container cases pass, alongside broker authority, budget, replay, credential isolation, proof and signature controls.
- Permit: **913 passed / 3 skipped** (two unavailable cloud-checkout integrations, one explicitly disabled live-model test/probe via `SKIP_LLM_TESTS=1`).
- Kernel: **978 passed + 323 subtests**, initially six skips. All four environment-dependent installed-package/PostgreSQL tests subsequently pass with pinned constraints and real PostgreSQL 16. Two existing Phase 4B reconciliation placeholders remain skipped. Separate conformance: **35 passed + 63 subtests**.
- Both final scripted malicious-hook rehearsals: agent/runner exit 0, **3 visible + 4 hidden passes**, four confirmed calls, **4,220 micro-USD** accounting each, anchored journals verified. Baseline delivers the synthetic canary; protected delivers none following a working positive control. Harness hook hashes remain unchanged. The generic scorer counts harness-planted test files as modifications; the separate hashes distinguish them from agent edits.
- Ruff lint/format, wheel/sdist build, clean Python 3.12.13 wheel installation and doctor pass. The original all-green local run preceded the five strict-resolution cases; the final full run was repeated on production commit `38c5c93133d362a0b295a2e5660645a2dd2575a1`.

Python 3.12.13, OpenAI SDK 2.54.0 and pinned components are unchanged: Protocol `a2e0e08fcd24b71eb1668204ba6bed00e4c63551`, Kernel `ead6a00aa38e7e3e21f6129a8565803f8ac48dd2`, Permit `b63cf8ac6968f72e45a082dc4fb91f3d4d08d689`, Scan `16388227a55a3b5a3ec392d1c70f3940b0c291c1`. Official Codex remains **0.166.0**, binary SHA-256 `f2e6c980c937e734644bed1b4a9a018d3e63a0ccbe71aafc85c86a8c6e4b462a`, image `sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269`. The standalone version probe emits the pre-existing stale-directory cleanup warning; execution tests pass. The runner, original task/hidden tests, lockfile, broker and release-gate files are unchanged.
