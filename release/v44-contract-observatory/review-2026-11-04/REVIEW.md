# V4.4 independent review addendum — 2026-11-04

Scope: independent verification of the V4.4 delivery (`9be175e`…`2c8e1f4`), one observatory defect found and repaired, and a more precise explanation of the V4.3 source-digest discrepancy. Earlier evidence, reports and freezes are unchanged; this addendum corrects one conclusion in `../REPORT.md` (see §4). No billable inference, real GitHub consequence, merge, tag or release occurred.

## 1. V4.3 live evidence, independently re-verified

A standalone verifier using only the Python standard library and `cryptography` (no Airlock imports) re-checked the original journal in the owner's live-evidence directory (`1-baseline-v4-3`):

- File hashes match `../live-evidence.json` (receipts `2b6cdd2b…`, result `3f3f8b08…`, checkpoint `49fb11f5…`, public key `24ff0482…`).
- All five Ed25519 receipt signatures (domain `actenon-airlock/receipt/v1\n`), the hash chain, and the checkpoint signature (5 entries, head `a65ee742…`) verify.
- Receipts 2 and 4: AMBIGUOUS, `response-schema` / `response-object`, event 0 `response.created`, `unexpected_fields: ["image"]`, terminal status `completed`, 54 and 57 events. Holds 681,765 + 694,570 = **1,376,335 micro-USD** (reservations, not provider bills). Receipt 5: DENY, run spend bound.

Limitation: the trusted key is the `public-key.json` stored beside the journal. No earlier out-of-band record pins it, so this proves internal consistency and signing by the run's key, not which key the supervisor generated. §6 adds a prerequisite for this.

Timeline check: each junit start timestamp precedes the commit that records it (e.g. full suite started 23:47:33Z, ran 217 s, commit 23:51:52Z), and exact-head CI for `2c8e1f4` started 23:52:11Z and passed all four jobs.

## 2. Official `image` schema re-checked

The current Responses retrieve reference declares `image: optional object { context_compression }` with no `or null`. `context_compression` is required and non-nullable, with values `"enabled"` | `"disabled"` ("Effective image context optimization policy"). The create (request) reference adds `auto`, the request default. Nothing found states model applicability or when the response echo appears. This matches the validator in `28fc303` exactly: omission or the one-member object with those two values only.

The documented top-level list now has 39 properties. All 39 are present in `../compatibility-matrix.json`; the matrix additionally carries `frequency_penalty`, `presence_penalty` and `store` (SDK or live history). No newly documented property is missing.

## 3. Observatory defect: realistically long streams (fixed)

The V4.4 tests used short synthetic streams (at most 16 events). Measured inputs:

| Source | Events | Structural tokens |
|---|---:|---:|
| Real Codex 0.166 request, real 8-tool inventory (container, mock provider, counts only) | — | 443–509 (echoed inventory 425, depth 11) |
| Live GPT-5.5 first turns, V4–V4.3 (signed receipts) | 42–68 | ≈2,050–2,360 (estimate) |
| Patch-writing turn (≈ one delta per output token) | ≈1,000+ | ≈10,000+ |

Old limits: 256 events and 8,192 structural tokens for the **whole** SSE body. For a valid stream the authoritative observer CONFIRMED:

- 258–408 events: the observatory reported **false** `completion/terminal-missing` and `stream-integrity/terminal-missing` (the terminal frame was beyond the cap).
- ≥ ~900 events: only `inspection-limit`, with no diagnosis at all.
- One oversized frame hid every independent defect in the terminal snapshot.

Authority was never affected. The defect matters because a live run that gets past the first response reaches exactly these turns, and the observatory existed to diagnose them.

Regression-first commit `9cb8344` records **8 expected failures** (`before-long-streams.txt`). Repair:

- Per-document guard (`MAX_NODES` 8,192 per frame, JSON body or request) plus a cumulative `MAX_TOTAL_NODES` 131,072 across parsed frames.
- Frames inspected in order up to `MAX_EVENTS` 4,096. After that, frames are skipped lexically, except up to `MAX_LATE_LIFECYCLE` 4 frames whose SSE `event:` name is a lifecycle snapshot. These are parsed, so terminal metadata, image policy, tool echo and usage are still diagnosed.
- `MAX_LINES` 65,536. Oversized or malformed frames are skipped individually and no longer abort the inspection.
- When any frame was not inspected: sequence continuity is not judged across the gap; a terminal not found is reported `terminal-not-inspected`, not `terminal-missing`; whole-stream consistency is disclosed as `stream-integrity-not-inspected`, not guessed. A partial frame cut by the line limit is not reported as a defect.
- Report adds `events_skipped` and the new limits. Report cap (16 KiB), issue/path/field caps and the authoritative observer are unchanged.

Adversarial 4 MiB bodies (named delta flood, unnamed tiny frames, blank/comment lines, lifecycle-snapshot flood, maximally nested frames, single 4 MiB string): observatory ≤ 0.42 s and ≤ 32 MiB peak traced memory (mostly the decoded body copy), report ≤ 3 KB, every case truncated and none confirmed (`adversarial-timing.txt`). These are deterministic work bounds, not OS quotas.

## 4. Source-digest discrepancy: origin established

`6e141812…` is the frozen runner's `digest_tree(src/actenon_airlock)`: sorted relative path, NUL, raw bytes, excluding `__pycache__`. A separately written reconstruction from Git objects at `208163b` reproduces it exactly (28 files).

`4e724a87…` was **never computed by any tool**. The pre-flight evaluator's local session transcript (Antigravity/Gemini session `058d6c9d`; content not committed) shows:

- First occurrence at step 3326, 23:15:46Z, inside model-authored scorecard text labelled "VERIFIED". No command output anywhere in the transcript contains it (`digest-provenance.json`).
- At 23:19:01Z it was carried into the V4.3 live prompt as the "expected" digest.
- That session then computed `32364460…` with `manifest.discover` (a different-purpose scanned-project fingerprint) and `6e141812…` with the runner identity, which is the value the live run recorded.
- A sweep of 85 revisions × 6 scopes × several byte schemes found no match.

The correct reading is an unverified, model-generated figure presented as verified. It is not evidence of drift or tampering, and not a second hashing algorithm. This supersedes the "unknown" conclusion in `../REPORT.md` §Source identity. That report's statement that the owner confirmed an edit is a claim this review could not check and does not rely on. Going forward, only digests produced by `scripts/source_identity.py` or the runner at the frozen commit should be quoted, and evaluator reports should cite the command that produced each digest.

## 5. Validation of this head

Tested production commit `6632cff`, source digest **`49a73cd88f4ce1ae7fd72334c78558aaa2069054d3f0d4ce52713e22eb12a25b`**. `scripts/source_identity.py` and the separate Git-object reconstruction agree, and the runtime tree matches Git. Exact counts are in `validation.json`.

- Regressions before repair (`9cb8344`): 8 of 8 fail as expected. The earlier regressions were also re-run on their pre-repair commits: `9be175e` gives 9 failed / 63 passed, `1c4ecf7` gives 30 failed / 72 passed, matching `../REPORT.md`.
- Full Airlock with real Docker 29.9.2: **1,980 passed, 0 failed, 0 skipped**. This includes all 29 real-container cases (Codex 6, Claude Code 9, mounts 12, GitHub 1, independent 1), the image/full-contract, observatory, accounting-replay, credential-isolation and source-identity suites, and 10 new long-stream cases.
- Real Codex inventory measurement (`real-inventory-size.json`): 4 requests, 8 tools each, no observatory truncation or issues; the authoritative observer confirmed each.
- Permit at the pinned `b63cf8a`: 913 passed, 3 skipped (two absent cloud checkouts, `SKIP_LLM_TESTS=1`).
- Kernel at the pinned `ead6a00`: 940 passed + 290 subtests, 44 skipped. 29 skips are the optional `mcp` extra, 1 `langchain_core`, 3 PostgreSQL DSN, 2 Phase 4B placeholders and 1 unpublished-candidate install check. Extras were deliberately not installed, to keep the pinned environment the next freeze binds unchanged. `../REPORT.md` records the fuller-environment Kernel run.
- Scripted malicious-hook controls (`--attack --test-hook`, no `--live`, `OPENAI_API_KEY` unset): both modes give agent and runner exit 0, 3 visible + 4 hidden passes, 4/4 confirmed responses and 4,220 micro-USD estimated accounting. Baseline: 2 agent canary deliveries. Protected: 0, with the harness positive control delivering (status 200). Harness hook files are unchanged. Journals and checkpoints verify ANCHORED with both the Airlock verifier and the independent one.
- Lint and format (CI scope), wheel and sdist build, clean wheel install, `airlock doctor`, and wheel/source byte parity (29 files) all pass.

Financial accounting is unchanged. The repair touches only `responses_observatory.py`, whose output the broker never reads (its only consumer copies it into the signed receipt). Budget formulas, settlement, reservation holds and replay refusal are untouched, and the full-suite accounting and replay tests pass. Reserved exposure remains distinct from provider billing everywhere.

## 6. Next frozen live trial — added prerequisites

`../LIVE_DIAGNOSTIC.md` remains authoritative; additionally:

1. The freeze must bind the final head of this PR (not `2c8e1f4`). Its `source_digest` must come from `python scripts/source_identity.py` at that exact commit.
2. Immediately after the run, the supervisor records `sha256(public-key.json)` out-of-band (outside the evidence directory) before anyone reads the journal, so offline verification has an independently pinned key.
3. If the run fails, the first failed response's signed `contract_observatory` record is the diagnostic input. If it shows `truncated: true` together with `terminal-not-inspected` or `stream-integrity-not-inspected`, the stream exceeded diagnostic bounds and those conclusions are absent, not negative.

## 7. Remaining unsupported or unverified

- Live `image` value and whether the rest of a live GPT-5.5 stream passes: still unknown until a live run.
- The real provider's tool echo may add properties beyond the authored echo used here. The observatory would now report them by public name or hash.
- Observatory hashes of unknown names are correlation identifiers, not confidentiality: predictable names can be dictionary-matched.
- Unsupported by design: hosted tools and nonzero hosted usage, image inputs or generated outputs, provider state (`conversation`, `previous_response_id`, `background`, stored prompts beyond the opaque echo), `prompt_cache_diagnostics`, `prompt_cache_options` (GPT-5.6+), unknown billing categories, undocumented `image` forms (null, `auto`, extra members).
- Inherited opaque echoes noted in `../COMPATIBILITY_MATRIX.md` (service tier, retention, stored-prompt metadata) still lack full semantic validation.
