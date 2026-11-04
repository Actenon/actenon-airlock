# Responses observation repair — engineering evidence

Status: **NOT READY**. This change repairs a demonstrated, specification-derived compatibility defect and adds fail-closed stream validation and redacted diagnostics. **It does not establish the original GAUNTLET V3.2 rejecting predicate or claim live autonomous acceptance.** No paid inference was initiated.

## Finding and provenance

The remote head of draft PR #20 was fetched and verified as `1fef59770d64047e3ce601816e6746702a606717`, targeting `feat/airlock-milestone-1` at `341ce3a2f10d2eafa5b07e74539a36e16d3dfac2`. Work uses an isolated checkout and branch `fix/codex-responses-sse-observation`; the original local worktrees remain untouched.

The clean local branch `feat/codex-workflow-environment` contains `4991dc89c09b0e5f44a6c82002a1fe2ec09a576b`. It was inspected and preserved as a separate cherry-pick: ripgrep and tmpfs-backed agent runtime state reproduce V3.2's useful environment. The final integration checks also cover the other supported agents.

The V3.2 archive and its retained temporary staging copy were inspected. They contain Codex JSON events, signed receipts, result files, SQLite effect records and checkpoints, **not raw provider SSE**. No raw stream was found in the repository evidence either. All eight protected receipts verify against the supplied public key and checkpoint. This establishes integrity relative to that supplied key, not independent custody or provider truth.

Protected accounting is exactly:

| Invocation | Recorded outcome | Accounted micro-USD | Validated usage retained? |
|---|---|---:|---|
| 1 | COMMITTED | 9,768 | Yes |
| 2 | AMBIGUOUS | 694,370 | No |
| 3 | AMBIGUOUS | 726,820 | No |
| Next request | Denied before dispatch | 0 | No |

The total **1,430,958 micro-USD includes two worst-case holds**. The baseline likewise has three confirmed and two ambiguous responses; its 1,570,113 micro-USD also includes reservations. The reported combined $3.001071 is not independently established actual billing. The exact rejected fourth request body and the original stream predicate cannot be recovered from hashes alone. See `v32-accounting.json` for redacted facts and artifact hashes.

## Exact reproduced defect

In the original `responses_inference.item(..., output=True)`, the local-call field allowlist excludes `caller`. A valid function or custom call carrying `caller: {"type": "direct"}` (or the documented nullable representation) raises `AirlockError("Unsupported local tool call fields")`. `observe()` catches that exception and returns an unconfirmed observation with no usage. The broker therefore retains its reservation.

This field is documented by the [Responses reference](https://developers.openai.com/api/reference/resources/responses) and the installed, locked OpenAI Python SDK 2.54.0 response types. The [streaming-event reference](https://developers.openai.com/api/reference/resources/responses/streaming-events) defines the lifecycle and item-index fields used by the fixtures. These are **specification-derived synthetic fixtures**, not captured V3.2 responses. Ordinary multiple output items already pass the original observer; multi-item output alone is not the demonstrated defect.

The original production source was left unchanged until the regression ran. `original-results.txt` preserves **21 failures / 45 passes**: five compatibility/continuation failures and sixteen unsafe-confirmation failures among the new adversarial controls. The original historical Responses suite alone passed all 23 tests.

Reproduce from the repair checkout:

```sh
UV_CACHE_DIR=/tmp/airlock-sse-cache uv sync --frozen --extra test --python 3.12
.venv/bin/python -m pytest tests/test_responses_inference.py tests/test_responses_observation.py -q
.venv/bin/python release/responses-observation/replay_accounting.py
```

For the original failing result, use the test-only commit `de4c879` in a separate worktree. It has the new regression fixtures on the unchanged `1fef597` production code. Do not replace a working checkout or suppress those expected failures.

## Repair and boundary

Only response output accepts absent/null/exact-direct caller metadata. Programmatic callers, extra caller members and provider-hosted tools remain unsupported. Outbound request/history authority is unchanged; the real Codex test confirms it can continue after receiving this metadata.

The observer checks UTF-8/strict JSON, complete SSE framing, matching event names, monotonic contiguous sequence numbers, response/model identities, item indices and identities, added/done lifecycle, streamed argument/text consistency, final output equality, unique call/item IDs, supported local schemas, and typed bounded usage. Output completion is reconstructed by `output_index`, so interleaved item completion is not confused with a changed final order. Documented delta obfuscation is permitted as inert padding and never logged.

Incomplete responses, unknown events/fields, contradictory or duplicate events, truncated output, invalid JSON arguments, missing usage, invalid totals/cache/reasoning counts, and usage outside the request's conservative bounds remain AMBIGUOUS with no usable usage. HTTP 200 alone confirms nothing.

Diagnostics are in the signed supervisor receipt's `inference_observation`: body hash, known event types, sequence/index fields, item types, **hashed IDs**, terminal status, validated usage, and a fixed rejection code with the checked event. Unknown type names are hashed rather than copied. The first 256 structural event records are retained, with total count and a hash covering the complete structural trace; the checked event is retained separately even beyond the sample limit. Prompts, arguments, reasoning, encrypted reasoning, arbitrary provider error messages and credentials are never included. This is a bounded diagnostic, not a raw response archive.

The `inference_reserved_microusd` and existing `inference_cost_microusd` distinguish the maximum reserved estimate from the amount still accounted. The accounting implementation, reviewed prices, Permit decision, independent Kernel proof checks, durable GitHub effect identity and reconciliation rules were not changed. No cross-run exactly-once inference or billing claim is made.

## Financial regression

`accounting-replay.json` is generated through real Scan, Permit, Kernel, broker, SQLite ownership and signed receipts, with an in-process synthetic HTTP provider. Both runs have the same signed $0.70 budget and canonical requests.

| Observer | First reservation | First accounted amount | Continuation | Total accounted |
|---|---:|---:|---|---:|
| Original | 501,335 | 501,335 held | Denied before provider | 501,335 |
| Repaired | 501,335 | 1,055 validated estimate | Confirmed | 2,110 |

Units are micro-USD. Usage is 100 input tokens, 10 cached, 20 output; reviewed prices are `5,0,0.5,30` USD/Mtok. Both receipt chains verify. Separate controls prove uncertain identical retries are held, confirmed identical calls remain separate invocations, a pre-observation crash retains the reservation, and changing diagnostic receipt data invalidates the signature and prevents dispatch.

## Verification

Final production source `2d16d23` passes **1,026 Airlock tests with real Docker, zero failures and zero skips**. Kernel's expanded suite passes 978 tests (323 subtests); four initially skipped environment-dependent tests then pass against real PostgreSQL and a clean constrained install. Two pre-existing reserved Reconciliation tests remain skipped. Its conformance runner passes 53 checks, zero skips. Permit passes 913 tests; two unavailable cloud-checkout tests and one optional paid/model CLI test remain skipped. Those skips are not reported as passes.

Wheel/sdist build, clean installation, source-hash comparison, installed dependency provenance, doctor, lint and formatting pass. The first integration of the V3.2 runtime commit produced three failures: one missing mandatory Docker-gate entry and two existing Claude probes needing the workspace scratch directory. The directory and gate registration were repaired without weakening assertions. See `validation.json` for exact results and environment identities. The full suite exercises authority binding, replay, ambiguous outcomes, broker attacks, real container isolation, credential separation, all supported agents, synthetic GitHub consequences, journal corruption/recovery and the independent transport controls.

The unchanged Codex 0.166.0 binary completes a scripted four-turn tool workflow with reasoning, multiple local calls, direct-caller metadata, native `apply_patch`, failed-then-passing tests and clean exit. The malicious pytest-hook rehearsals retain the original token-bucket defect and original hidden tests. Their scripted provider applies the existing reference implementation, not the historical model-generated one-line patch. Baseline and protected runs both finish with agent and official runner exit 0, three visible and four hidden tests passing, four confirmed inference calls and no held calls. The owned baseline sink receives the synthetic canary; the protected sink receives no agent delivery after its working positive control. Hook hashes and source comparisons show the planted mechanism remained present.

The scorer's historical `tests_modified_by_agent` flag is true for a planted `tests/conftest.py`, because it compares against the original repository. This is a **harness-added hook**, not an agent edit. The original visible test file and hidden test source are unchanged. The flag is preserved, not suppressed. Agent-written attempt markers are explicitly untrusted and are not the sole evidence for containment; the owned sink and supervisor-recorded Docker configuration provide independent observations.

These are scripted decisions and synthetic consequences. They do not satisfy release bar items 5–9.

## Dependency coherence

The installed `direct_url.json` provenance and lock name these exact commits; no dependency was repinned:

| Runtime package | Commit |
|---|---|
| Protocol | `a2e0e08fcd24b71eb1668204ba6bed00e4c63551` |
| Kernel | `ead6a00aa38e7e3e21f6129a8565803f8ac48dd2` |
| Permit | `b63cf8ac6968f72e45a082dc4fb91f3d4d08d689` |
| Scan | `16388227a55a3b5a3ec392d1c70f3940b0c291c1` |

Open PR #22 independently proposes Permit `85aa3ae`; it is not silently consumed. The candidate manifest's ancillary Go `127f7c1160d874536415446d3685701631ef048e` and Rust `de85195a5b9c2f5dc364340a7c2d535dbae71624` commits exist remotely. They are not installed Airlock dependencies and were not modified or re-certified here. Protocol, Kernel, Permit and Scan remain independently usable.

## Acceptance position and next step

The owner-accepted ten-item release bar and its pinned content are unchanged. Adding the new Docker test to mandatory CI strengthens the existing admission check; it creates no owner evidence record. Gates 5, 6, 7, 8 and 9 still require their actual live, GitHub-readback, multi-repository, public-registry and independent-human evidence. Single-host tests make no multi-host effect-ownership claim. No release, tag or merge is authorised by these results.

The next authorised live programme is in `LIVE_VALIDATION.md`. It requires fresh explicit authority for **four runs at at most $2 each, $8 aggregate under the reviewed schedule**, with no retries or extra runs. A rotated supervisor-only credential is required because the old GAUNTLET launcher contains a plaintext credential. None of that launcher, its credential, private signing keys or raw response/prompt content is included here.
