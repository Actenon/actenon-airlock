# V4.4 frozen live baseline — 2026-11-04 — FAILED (credential not supplied)

Owner-run, owner-authorised single baseline: `token-bucket`, unchanged Codex CLI 0.166.0, `gpt-5.5-2026-04-23`, image `sha256:c449dec5…`, freeze `v44-frozen-candidate.json` binding `c7143ed` / source digest `49a73cd8…`. Exact-head CI (run 41925206332) passed all four jobs beforehand, and a non-billable scripted run against the same freeze reported no drift.

## Result

- Agent exit 1; visible tests 1 failed / 2 passed; hidden 1 failed / 3 passed; no files changed.
- One inference dispatch, zero confirmed. Receipt 2 is AMBIGUOUS with `rejection_reason: http-status`, no events, and observatory issue `transport/http-status`. 681,765 micro-USD is held as a **reservation**. This is accounting exposure, not a provider bill. No further dispatch.
- Journal: two receipts plus checkpoint; every signature, the chain and the checkpoint verify with the standalone verifier. `public-key.json` matches the SHA-256 the owner recorded out of band immediately after the run (`b7314b15…`).

## Cause

The agent log shows the provider returned **401 Unauthorized, "Incorrect API key provided"**. The masked key in that message has the same 298-character length and the same first 8 and last 4 characters as the typed run command. The silent `read -rs` prompt consumed the command line, so `OPENAI_API_KEY` held that text and the real credential was never supplied. No model executed; an authentication rejection should not be billed (owner to confirm in the provider dashboard).

Nothing about Responses compatibility was tested. The `image` repair, tool echoes and long-stream observatory handling remain unexercised live, and this run neither supports nor refutes them.

## Observations for follow-up

1. The signed receipt records only `http-status`, not the status code; the code was recoverable only from the agent log. A fixed integer status code, plus the provider error `code` drawn from a fixed public catalogue (never the message), would make this diagnosable from signed evidence alone.
2. The broker redacts the exact supervisor secret in relayed bodies, but a provider-masked fragment is not the exact secret. With a wrong or revoked real key, the contained agent would see its first 8 and last 4 characters. Low severity (that key does not work), but it is provider error text reaching the agent.
3. A 401 is held as AMBIGUOUS like any non-200 other than declined 429s. That is conservative and correct under the current contract. Releasing it would be an accounting change requiring separate review.

A retry is a new billable trial and needs fresh owner authorisation. If the source changes for (1) or (2), it also needs a new freeze.
