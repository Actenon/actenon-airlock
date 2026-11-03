# V4.2 live-observed response compatibility repair

## Finding and confidence

**High confidence:** V4.1 failed at event zero, `response.created`, because the evaluated observer did not admit three response properties. The exact evaluated and starting remote PR #23 head was `eeea658882d498258f783f0031b4ef6bdc6d415e`. Offline verification of `/Users/ross/src/actenon-audit/live-codex/1-baseline-v4-1/` verifies all five receipt signatures and the five-entry checkpoint. Receipts 2 and 4 each contain exactly these unexpected property identifiers:

| Property | SHA-256 of JSON string encoding |
|---|---|
| `presence_penalty` | `08cddebc8497c80ff162929c9a3dc3878a7cd855802eb092864dfa536182a419` |
| `frequency_penalty` | `6d0b2264042111e0d5f4058f083e1c4ef190cd3003657fa8015115ab2855be27` |
| `tool_usage` | `bedfbed57f7a6b61ee0de6808fb49c1a366eb7543f47f950bdb55a8411b5c9e2` |

All three matches were recomputed with the application's JSON-string encoding. The two outcomes remain AMBIGUOUS, retaining **681,765 + 697,815 = 1,379,580 micro-USD**. The next request was refused; agent exit was 1. These are reservations, not confirmed provider charges. The result's pre-checkpoint status says UNANCHORED; offline verification with the completed checkpoint establishes ANCHORED integrity.

**Unknown:** actual values of these properties, and whether the complete live streams would pass the repaired validator. No values were retained in the structural diagnostics. No credentials, prompts, reasoning, private response bodies or `agent.log` were inspected. No claim is made that the live properties were zero or null. Historical V4/V4.1 evidence remains untouched. Safe extraction and file hashes are in `live-evidence.json`; signature verification is in `live-evidence-verification.json`.

## Exact SDK and semantic review

The locked environment is Python 3.12.13 / OpenAI SDK **2.54.0**. None of these three names is a declared field of its Response model. `schema-review.json` records the exact model field inventory, file SHA-256, unchanged outbound field inventory, and the retrieved official Responses-reference hash. SDK permissiveness is not used to generate an acceptance allowlist.

The [current Responses reference](https://developers.openai.com/api/reference/resources/responses/methods/create) documents `tool_usage`, separately from base-model `usage`. Both `image_gen` and `web_search` are required inside a present object. Image usage requires input/output/total integer counts and input text/image details; cache counts, cache details and output details are optional. Web usage requires integer `num_requests`. Image calls with incomplete records may be omitted; a missing cache count means unknown. Web counters exclude discounted searches and page-opening actions. Consequently these counters are not proof that no hosted activity occurred, nor a replacement for billing records.

The current Responses page and pinned Response model do not declare the two penalty fields. Their names are established by signed live hashes. The [official Chat Completions reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create) defines both as nullable numbers in **[-2, 2]**, default **0**. Presence penalties depend on whether a token appeared; frequency penalties depend on how often. This is evidence for the parameter semantics, not proof that nonzero penalties are supported by GPT-5.5 Responses. Airlock's approved request cannot send either field.

| Property | Accepted response-only subset | Refused |
|---|---|---|
| Presence/frequency penalty | Absent, null, integer zero or floating-point zero (including negative zero). Null is treated conservatively as unset metadata, not evidence of an actively chosen setting. | Boolean, string, object, array, nonfinite number, and every nonzero number, including values inside the general API range. |
| `tool_usage` | Absent, or the documented object with **every present counter exact integer zero**, both required families and all required nested members. Optional image details may be omitted. | Null, `{}`, absent required members, extra properties at any depth, malformed types, float/bool counts, negative or positive counts. |

No undocumented empty-object representation is assumed: the zero-activity object is `tests/fixtures/response-zero-tool-usage.json`. Optional cache detail omission remains unknown rather than being rewritten to zero. Acceptance remains contingent on outbound hosted-tool prohibition, local-only output validation and every existing completion/usage check. The metadata cannot authorize searches, image generation, code execution, provider state or any new consequence. Nonzero hosted activity is unsupported and unpriced, never priced at zero.

## Regression, implementation and diagnostics

Test-only commit **`ff037f3`** precedes production edits. Against the unchanged evaluated observer: **196 failed / 269 passed**. `before-repair.txt` and XML preserve the reproduction. These expected failures establish positive compatibility/accounting gaps and missing semantic diagnostics. The independent fixtures are not reconstructed live values.

Production commit **`c957216`** changes only `responses_inference.py`, plus test/evidence files. The explicit allowlist gains three names with explicit validators. Checks run for creation, progress, completion and nonstreaming JSON. Equivalent absent/unset/zero representations are permitted; any unsupported snapshot fails even if later replaced by zero. There is no change to requests, budget formulas, Permit, Kernel, consequence dispatch, replay, credential isolation or the release bar. Shared broker routing still selects the Responses observer only for the existing Responses contract; other providers retain their own observer.

The 465 new cases cover absent/null/default combinations, all optional image-detail combinations, every count leaf, required omissions, malformed/unknown objects, nonfinite and nonzero penalties, metadata changes at every snapshot, completed/incomplete/truncated/contradictory output and usage, hosted-tool refusal, accounting continuation and replay. The existing real Codex direct-caller test now carries all three supported fields through four turns, retaining all prior assertions.

Diagnostics distinguish `response-unsupported-penalty`, `response-tool-usage-schema`, and `response-hosted-tool-usage`. They identify `response-metadata` or `response-tool-usage` stage and a fixed schema path, without values. Unknown nested properties use the existing bounded scheme: at most 16 fixed public identifiers or JSON-name SHA-256 hashes, total count and truncation flag. No attacker-selected path components are copied. Six nested injection tests verify absence of secret names/values from receipts and console; tampering with the diagnostic invalidates the signed receipt. Hashes are correlation identifiers, not encryption. Existing top-level diagnostics remain intact.

## Financial lifecycle

`replay_accounting.py` executes the actual broker/Permit/Kernel with synthetic HTTP responses and a signed **700,000 micro-USD** bound:

| Outcome | Initial reservation | After first response | Second request | Total retained/accounted |
|---|---:|---:|---|---:|
| Evaluated observer, valid zero metadata | 501,335 | 501,335 held | Refused | 501,335 |
| Repaired observer, valid zero metadata | 501,335 | 1,055 validated estimate | Confirmed | 2,110 |
| Repaired, nonzero web usage | 501,335 | 501,335 held | Refused | 501,335 |
| Repaired, nonzero image usage | 501,335 | 501,335 held | Refused | 501,335 |
| Repaired, partial stream | 501,335 | 501,335 held | Refused | 501,335 |

The valid first result leaves 698,945 micro-USD; the second reserves 501,465 before settling. The model estimate is 90 ordinary input, 10 cached input and 20 output tokens at the unchanged reviewed schedule, totaling 1,055 micro-USD. Hosted usage is validated separately and contributes no accepted nonzero activity. Unsupported outcomes expose no confirmed model usage and release no reservation. Identical unresolved requests stay blocked despite changed trace/cache metadata. Every replay journal verifies. `accounting-replay.json` contains exact figures; additional tests cover incomplete, malformed and nonzero-penalty outcomes. No provider billing was incurred or inferred by this work.

## Validation and remaining blockers

Exact counts, skips and identities are recorded in `validation.json`. The final delivery records the exact review head and GitHub Actions run; source/dependency/image binding for the next run is frozen separately after all non-billable checks pass. No live inference is launched by this repair.

- Focused Responses: **720 passed**, including **465 new cases**.
- Full Airlock, genuine Docker 29.9.2: **1,663 passed, zero failures/skips**. All six unchanged-binary Codex cases pass; the suite includes other-agent, broker, credential isolation, Permit/Kernel integration, budget, replay and signed-evidence controls.
- Permit: **913 passed, three skips** (two unavailable cloud-checkout integrations, one explicitly disabled live-model test). `SKIP_LLM_TESTS=1` prevents even the model availability probe.
- Kernel: **978 passed + 323 subtests**, initially six skips. All four environment-dependent installed-package/PostgreSQL cases subsequently pass with the pinned constraint and a disposable real PostgreSQL 16 server. Two pre-existing unimplemented Phase 4B reconciliation cases remain skipped. Separate conformance: **35 passed + 63 subtests**.
- Both scripted malicious-repository-hook controls: runner/agent exit 0, **3 visible + 4 hidden passes**, four confirmed calls and **4,220 micro-USD** accounting each; journals verify as ANCHORED. Baseline sink sees the canary; protected sink sees none after a working positive control. Hook file hashes remain unchanged. The generic scorer counts harness-planted tests as modifications; separate hashes distinguish these from agent changes.
- Ruff lint/format, wheel/sdist build, clean Python 3.12.13 wheel install and doctor pass. Codex version is **0.166.0**, binary SHA-256 `f2e6c980c937e734644bed1b4a9a018d3e63a0ccbe71aafc85c86a8c6e4b462a`, image `sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269`. The standalone version probe emits the existing stale-directory cleanup warning; real execution cases pass.

Pinned components are unchanged: Protocol `a2e0e08fcd24b71eb1668204ba6bed00e4c63551`, Kernel `ead6a00aa38e7e3e21f6129a8565803f8ac48dd2`, Permit `b63cf8ac6968f72e45a082dc4fb91f3d4d08d689`, Scan `16388227a55a3b5a3ec392d1c70f3940b0c291c1`. The lock and existing acceptance programme are unchanged.

Synthetic traffic proves the reviewed subset is accepted and unsupported values remain unconfirmed. It does not prove the discarded V4.1 values fit that subset, that a real model completes the original task, or that billing matches accounting estimates. The next diagnostic is **one** unchanged official Codex baseline on the original token-bucket task and hidden tests, pending fresh owner authorization, a $2 estimated per-run maximum, independently enforced cumulative spending and a fresh supervisor-only credential. See `LIVE_DIAGNOSTIC.md`. Existing owner-accepted release gates remain unchanged; PR #23 stays draft.
