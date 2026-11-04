# V4.4 authentication-failure hardening

Source under test: `53fc2ae` (source digest `bd7904d2a305b9fe2daa1ff4efb326684bb572b3dbb59d41594a4f508c6fe503`, reproduced independently from Git objects). Exact counts are in `validation.json`. No billable inference, real GitHub consequence, merge, tag or release occurred. The failed V4.4 live trial and its evidence (`../v44-contract-observatory/live-2026-11-04/`, owner directory `1-baseline-v4-4`) are unchanged; all five recorded hashes still match.

## Incident recap

The frozen run at `c7143ed` sent a swallowed shell command as the API key. The provider returned 401 "Incorrect API key provided: `<masked>`". Airlock correctly held the inference AMBIGUOUS, but:

1. the signed observation said only `http-status`;
2. the provider body (including the masked credential echo) and all provider headers were relayed to the contained agent. The broker redacts the exact secret, but a masked fragment is not the exact secret.

## Changes

| Commit | Change |
|---|---|
| `4a61a47` | Regression first: **44 expected failures**. The 16 passing cases show reservations and retry refusal were already correct (`before-hardening.txt`). |
| `9f7a3b6` | `provider_errors.status_diagnostic`: the signed observation gains `http_status` (integer 100–599, else `invalid`), `http_status_class`, `provider_error_body` (`json`/`empty`/`oversized`/`malformed`/`unexpected-shape`), and `provider_error_code`/`provider_error_type` **only on exact allowlist match** (otherwise `unrecognised`/`invalid`). The error body is parsed only up to 64 KiB, rejecting duplicate keys and non-finite numbers. 429 replies previously returned without diagnostics; they now keep them, with `provider-declined` for the documented declines. Applies to both inference contracts. |
| `dfdd975` | `ProtectedBroker.relay_policy`: after observation and evidence hashing over the received bytes, a non-200 reply from an inference provider is replaced by the same status, `content-type: application/json` only, and a constant error body (OpenAI- or Anthropic-shaped, allowlisted code/type at most). No provider text, header, cookie, organisation, request id or masked fragment reaches the agent. Successful replies and generic HTTP are not rewritten. |
| `53fc2ae` | Supervisor credential pre-flight (`credential_preflight.py`, runner `--live` and new `preflight` mode). See below. |

**Accounting is unchanged.** A 401, 403, 5xx, malformed or misleadingly coded reply stays AMBIGUOUS with its full reservation held, and an identical retry is refused. Only the two documented 429 declines (`rate_limit_exceeded`, `insufficient_quota`) release, exactly as before. A 401 carrying `insufficient_quota`, or a 429 carrying `invalid_api_key`, is not reclassified. Diagnostics never feed confirmation, decline, usage or budget.

### Credential pre-flight

- **Local check**, before the drift check, Docker, setup, reservation or dispatch. It refuses missing, empty, whitespace, control characters, non-ASCII, length outside 20–512, a prefix other than `sk-`, and characters outside `[A-Za-z0-9_-]`. The refusal is fixed text plus the input length. The V4.4 swallowed command is refused as `whitespace, unexpected-characters; 298 characters`.
- **One authentication check**, after the drift check and the `$2` authorisation check: `GET https://api.openai.com/v1/models/<frozen model>`, no body, no prompt, no redirects, no proxy environment, 15 s timeout. A 200 is recorded as `authenticated` with the explicit caveat that it is *not* proof of entitlement, quota, spend limit or billing. 401/403 → `rejected`, 404 → `model-unavailable`, other → `unavailable`, transport error → `unreachable`; exception text is never copied. Any outcome other than `authenticated` stops the run with no inference. The result is stored in `result.json` as `credential_preflight`.
- **Sources**: `OPENAI_API_KEY`, or `--credential-file` (an owner-only, non-symlink, single-line regular file), never both. The key stays in the supervisor process and is never printed or persisted.

## Verification

- New synthetic regressions (`test_inference_provider_errors.py`, `test_credential_preflight.py`): **60 pass**. They cover 401 with full, masked and foreign fake keys; 403; misleading 401/429 codes; 500 and 503 text; empty 502; malformed, duplicate-key, non-object, secret-valued, non-string-code and 200 KB bodies; duplicate secret-bearing headers; the Anthropic contract; documented 429 declines; and unchanged success. Every case checks that the agent reply, the relay record and the whole signed receipt journal contain no key, masked key, prefix or suffix fragment, `****` or `secret`. It also checks the signed observation values, the held reservation and the refused retry.
- **Real unchanged Codex 0.166.0 in its container, provider 401 echoing keys** (scratch test; summaries `e2e-real-codex-401-{before,after}.json`):
  - Frozen V4.4 source: Codex's console showed the full fake key, the masked key and the marker, and the signed observation had no status.
  - This head: Codex saw status 401 and the fixed Airlock message only. There were zero leak markers across the console and 24 run files. The signed observation reads `http_status 401`, `invalid_api_key`, `invalid_request_error`, `json`, and the outcome stayed AMBIGUOUS.
- Full Airlock suite with real Docker 29.9.2 and all three images: **2,040 passed, 0 failed, 0 skipped**. That covers Responses, broker, budget and accounting replay, credential isolation, receipt and checkpoint integrity, observatory, and 29 real-container cases.
- Scripted malicious-hook controls (no `--live`, `OPENAI_API_KEY` unset): both modes give agent and runner exit 0, 3 visible + 4 hidden passes, 4/4 confirmed and 4,220 µUSD estimated. Agent canary deliveries: baseline 2, protected 0, with the positive control delivering in both. Both journals verify ANCHORED with the standalone verifier.
- Lint and format (CI scope), wheel and sdist, clean wheel install, `doctor`, and wheel/source byte parity (31 files) all pass.
- Permit and Kernel were not re-run: their pinned commits and this change's dependency surface are unchanged since the 2026-11-04 review run (913 / 940 passed there).

## Limits

- The allowlists hold public, documented codes; recognising a code grants nothing. Unknown codes are recorded only as `unrecognised`.
- The agent loses provider `retry-after` and `request-id` on failures. Codex runs with zero retries here.
- The pre-flight's 200 depends on the provider's model-lookup semantics. A key can authenticate and still lack quota or entitlement; that would surface as an AMBIGUOUS or declined inference, with its reservation handled as above.
- The status of a 200 reply is recorded too, but diagnostics never establish billing.
