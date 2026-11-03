# V4 response-schema repair — review candidate, NOT READY

No paid inference was initiated. PR #23 remains draft; no merge, tag, publication, dependency-pin change, or release-bar change is part of this repair.

## Finding and confidence

The supplied V4 Trial 1 evidence reports unchanged Codex 0.166.0, genuine GPT-5.5 inference, agent/runner exit 1, five of seven independent tests passing, and two AMBIGUOUS dispatches. Both diagnostics identify `response-schema`, checked event 0, `response.created`. Reservations were **681,765** and **697,270 micro-USD**, totaling **1,379,035 micro-USD**. A subsequent request exceeded the $2 bound. These holds are not confirmed provider billing. Trial 2 did not run.

**High confidence, conditional on the supplied diagnostic:** the creation object contained at least one unsupported top-level field. The stream validator had already established a dictionary with a response ID; the next `response-schema` predicate rejects additional keys, before examining their values.

**Established independently:** SDK **2.54.0**, exactly pinned in `uv.lock`, has three Response fields absent from the evaluated observer: `conversation`, `moderation`, `prompt_cache_options`. Airlock additionally recognizes `store` and `access_programs`, both seen in official examples. `sdk-comparison.json` records the complete sets, types and source hashes. This difference is not proof of any live field's presence.

**Not established:** V4's actual event-zero field-name set or values. The supplied diagnostic has no key inventory. `_Trace.record` stores fixed event metadata, hashed IDs and a body digest, from which keys cannot be reconstructed. Searches of the earlier repair workspaces and known local GAUNTLET evidence directory did not locate the V4 artifact. Its location was requested; V4 signatures have not been independently reverified in this session. No credentials, prompts, reasoning or raw live bodies were accessed. Historical evidence and the previous programme remain unchanged.

## Semantic review

Sources reviewed on 2026-11-03: the exact installed SDK source; the [official response reference](https://developers.openai.com/api/reference/cli/resources/responses/methods/retrieve), [conversation-state guide](https://developers.openai.com/api/docs/guides/conversation-state), [moderation guide](https://developers.openai.com/api/docs/guides/moderation), and [prompt-caching guide](https://developers.openai.com/api/docs/guides/prompt-caching). Current documentation contains extensions beyond the pinned SDK; those are not automatically admitted.

| Class | Properties / security consequence |
|---|---|
| A: descriptive or echoed metadata | `created_at`, `instructions`, `metadata`, `temperature`, `top_p`, `reasoning`, `text`, `top_logprobs`, `truncation`, `user`, `safety_identifier`, `prompt_cache_key`. The supervisor does not derive execution authority from these response echoes. Their contents can be sensitive and are not added to diagnostics. |
| B: output, completion and accounting | `id`, `object`, `model`, `status`, `output`, `usage`, `error`, `incomplete_details`, `completed_at`, `max_output_tokens`, `service_tier`. Existing lifecycle, identity, output and usage checks remain mandatory. Service-tier metadata does not change signed prices; accounting remains an estimate under the reviewed schedule. |
| C: provider state or persistence | `store`, `background`, `previous_response_id`, `conversation`, `prompt`, `prompt_cache_options`, `prompt_cache_retention`. Outbound authority stays unchanged: explicit `store:false`, inline history, no conversation or previous-response reference. Existing cache-retention metadata is distinct from conversation persistence. No new populated state reference is accepted. |
| D: tools or external capabilities | `tools`, `tool_choice`, `parallel_tool_calls`, `max_tool_calls`, `access_programs`. Existing local-tool/output validation and programmatic-execution refusal remain unchanged. Response metadata cannot authorize hosted tools or consequence dispatch. |
| E: extensions | Every other field stays unsupported, including current-doc `image` and `prompt_cache_diagnostics`. Those two public names are diagnostic identifiers only. |

This is a focused compatibility repair, not a claim that every pre-existing descriptive field is exhaustively SDK-validated.

| Candidate | SDK/documented shape | Supported value and reason |
|---|---|---|
| `conversation` | Optional object with required string `id`; identifies the conversation receiving input/output items. | Absent or null only. `store:false` alone does not establish absence of conversation persistence: conversation items have separate retention semantics. This contract also forbids requesting a conversation. A populated reference is therefore unconfirmed. No live null/absence guarantee is claimed. |
| `moderation` | Optional object with `input` and `output`. Each is a `moderation_result` (model string, flagged boolean, category booleans/scores and text/image modality arrays) or an error (type, code, message). | Absent or null only. The feature returns results for requested moderated completions; Airlock does not authorize that request option. Populated results, errors, empty objects and extra nested properties remain unsupported, rather than being treated as completion evidence. |
| `prompt_cache_options` | Optional object; pinned SDK requires mode `implicit`/`explicit` and ttl `30m`. Current docs add further options. Supported for GPT-5.6 and later. | Absent or null only for this contract. No GPT-5.5 cache-options capability is enabled; all populated forms remain unconfirmed. |

Absent and null represent the same supported state. The check runs on creation, progress and completion snapshots, and on nonstreaming JSON. Any transition to a populated value fails independently of a later null value.

The complete SDK fixture check also independently reproduced rejection of documented `usage.input_tokens_details.cache_write_tokens: 0`. The repair accepts **only exact integer zero**, or absence for older shapes. Boolean, null, float, negative and positive counts remain unconfirmed. GPT-5.6 cache-write pricing is outside this contract; no positive count is silently priced at zero. No claim is made that V4 emitted this field. Accounting formulas and token totals are unchanged.

## Regression and implementation evidence

The test-only commit `30bdd78af1cbb62801f75ac4b90437a2685d4bc9` precedes production edits: **40 failed / 106 passed**, comprising 34 positive metadata/accounting failures and six missing-diagnostic failures. The later zero-cache-write regression failed **16 positive cases**, with 10 adverse controls passing, before its production correction. Replaying the final 172-case compatibility file against the evaluated observer yields **56 failed / 116 passed**. These are intentional reproductions, not hidden failures in the repaired source.

Fixtures are independent documented shapes, not captured provider responses. They cover each candidate and every absent/null combination, JSON/SSE, complete SDK object validation, valid prior metadata, wrong types, nested properties, stateful references, unknown fields, contradictory lifecycle values, correct completion, incomplete/partial streams, invalid usage/output, financial settlement, replay and unchanged outbound refusal. Existing assertions were preserved. The real Codex direct-caller continuation test additionally receives all three null fields while exercising reasoning, multiple local calls, native patching and tests.

Production changes are confined to `responses_inference.py`. Permit, Kernel, broker dispatch, credentials, prices and replay ownership are unchanged.

## Safe structural diagnostic

Unknown top-level properties retain reason `response-schema` and add `validation_stage: response-object`. `unexpected_fields` contains at most 16 identifiers, plus total count and truncation flag. Fixed public catalogue names are literal identifiers; other names become `sha256:` plus the SHA-256 of their JSON string encoding. Known names precede hashes deterministically. Values are never copied. A populated candidate reports `response-unsupported-metadata`, stage `response-metadata`, and only its fixed `rejected_field` name.

The existing signed `inference_observation` receipt covers these additions. Tests inject secrets in arbitrary names/values, verify absence from receipts and console output, and show that changing the field diagnostic breaks signature verification. Hashes are correlation identifiers, not encryption. Existing body bounds, event bounds and checked-event context remain in force.

## Financial lifecycle

`replay_accounting.py` uses the actual Scan/Permit/Kernel/broker with an HTTP mock and a signed **700,000 micro-USD** run limit:

| Observer / response | First hold | First validated estimate | Second dispatch | Total retained/accounted |
|---|---:|---:|---|---:|
| V4 candidate / null metadata | 501,335 | none | Refused | 501,335 |
| Repaired / null metadata | 501,335 | 1,055 | Confirmed; initial reservation 501,465 | 2,110 |
| Repaired / populated metadata | 501,335 | none | Refused | 501,335 |
| Repaired / partial stream | 501,335 | none | Refused | 501,335 |

All journals verify. Ambiguous repeats are refused even with changed client trace/cache metadata. After a valid first call, 698,945 micro-USD remain; after a held first call, only 198,665 remain. The 1,055 estimate comprises 90 ordinary input tokens, 10 cached input tokens and 20 output tokens at the unchanged reviewed prices. These are synthetic accounting estimates and reservations; actual provider charges are neither incurred nor inferred here.

## Validation and identities

Production commit: `a00e71ec4cb197f612c17164e14f18ead0dab45e`. Exact final results and source/dependency identities are in `validation.json`. The four dependency commits remain Protocol `a2e0e08fcd24b71eb1668204ba6bed00e4c63551`, Kernel `ead6a00aa38e7e3e21f6129a8565803f8ac48dd2`, Permit `b63cf8ac6968f72e45a082dc4fb91f3d4d08d689`, Scan `16388227a55a3b5a3ec392d1c70f3940b0c291c1`.

Actual final results:

- Full Airlock with real Docker 29.9.2: **1,198 passed, zero failed/errors/skipped**. This includes six unchanged-binary Codex container cases and the credential-isolation, stream-integrity, receipt, replay, budget, Permit/Kernel integration and containment suites.
- Focused Responses tests: **255 passed**; the new compatibility file contains 172 cases. All old assertions are retained.
- Kernel: **978 passed + 323 subtests**, initially six skips. All four environment-dependent skips pass separately with PostgreSQL 16 and the pinned Protocol install constraint. Two pre-existing Phase 4B reconciliation placeholders remain skipped. Additional conformance run: 35 passed + 63 subtests.
- Permit: **913 passed**, three skips: two unavailable-cloud integration cases and one deliberately disabled live-model test (`SKIP_LLM_TESTS=1`). No inference probe was attempted.
- Both final malicious-hook rehearsals: agent/runner exit 0, three visible and four hidden passes, four confirmed calls, 4,220 micro-USD accounting each, anchored signatures/checkpoints verified. Baseline delivered the canary; protected delivered none after a working positive control. Harness-planted hook hashes stayed unchanged. The generic scorer counts planted test files as changes; the separate hash evidence distinguishes them from agent edits.
- Lint/format, wheel/sdist build, clean wheel installation and doctor pass. Clean-wheel verification used Python 3.14.6; the frozen source test environment uses Python 3.12.13. The Codex binary SHA-256 remains `f2e6c980c937e734644bed1b4a9a018d3e63a0ccbe71aafc85c86a8c6e4b462a`. Its standalone version probe emitted a stale temporary-directory cleanup warning; all six execution cases passed.

Reproduce without inference:

```sh
uv sync --frozen --extra test --python 3.12
.venv/bin/python -m pytest tests/test_response_schema_compatibility.py tests/test_responses_observation.py tests/test_responses_inference.py -q
.venv/bin/python release/v4-response-schema/replay_accounting.py
AIRLOCK_TEST_PROTECTED_IMAGE=actenon-airlock-compute:dev \
AIRLOCK_TEST_CODEX_IMAGE=actenon-airlock-codex-cli:v1 \
AIRLOCK_TEST_CLAUDE_CODE_IMAGE=actenon-airlock-claude-code:v1 \
.venv/bin/python -m pytest -q
```

Build the three images from their existing Dockerfiles first; supply no real inference credentials. GitHub Actions must be checked on the final review head; the local counts above do not substitute for CI.

No synthetic test establishes that the original live response now passes, that real autonomous coding completes, or that final provider billing equals the estimates. The unchanged release gates remain outstanding. See `LIVE_VALIDATION.md` for a fresh freeze and separately authorized cumulative spending control; the old V4 freeze must not be reused.
