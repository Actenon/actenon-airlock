# V4.4b one-run live baseline — prepared, NOT AUTHORISED

Supersedes the V4.4 freeze for any future run. **Updated after the credential-isolation audit** (`../v44b-credential-isolation/REPORT.md`): the freeze must bind a head at or after `380bcc6` (Anthropic-key guard, `../v44b-anthropic-key-guard/REPORT.md`); any freeze bound to an earlier head, including `cce2404`, is void. The credential must be an **OpenAI** API key. Do not reuse `v44-frozen-candidate.json` (`c7143ed`). The new freeze binds the clean final head of this PR after exact-head CI passes, and only `run.py freeze` at that exact commit produces it. Its `source_digest` must equal `python scripts/source_identity.py` at that commit.

Everything in `../v44-contract-observatory/LIVE_DIAGNOSTIC.md` still applies: one `baseline --task token-bucket` run, unchanged official Codex CLI 0.166.0, `gpt-5.5-2026-04-23`, original task and hidden tests, no retries, no second trial, scoring unchanged. The run must not proceed without:

1. fresh, explicit owner authorisation of this freeze and one billable run;
2. a cumulative spending ceiling enforced outside the runner (e.g. a provider project budget);
3. the $2 (2,000,000 µUSD) per-run estimated bound (`--authorized-usd 2`);
4. a valid supervisor-only credential that never enters the repository, image, command line, logs, evidence or agent environment.

## Credential loading (replaces the silent `read -rs` step)

Store the key once in the macOS login Keychain. The prompt is hidden and asks for the value twice, so a pasted command cannot silently become the key:

```text
security add-generic-password -U -a "$USER" -s actenon-airlock-live -w
```

Then run the non-billable pre-flight. The key exists only in that one process's environment; shell history records only the `$(...)` text:

```text
OPENAI_API_KEY="$(security find-generic-password -a "$USER" -s actenon-airlock-live -w)" \
  .venv/bin/python acceptance/codex-cli/run.py preflight \
  --image sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269 \
  --config <new frozen config>
```

It must print `"outcome": "authenticated"` with `"http_status": 200`. It sends no prompt and starts no inference. Any refusal is fixed text, and nothing is created or reserved.

An owner-only (`chmod 600`), single-line, non-symlink file via `--credential-file <path>` is the alternative. Never supply both sources.

## The run (only after authorisation)

```text
OPENAI_API_KEY="$(security find-generic-password -a "$USER" -s actenon-airlock-live -w)" \
  .venv/bin/python acceptance/codex-cli/run.py baseline --task token-bucket \
  --image sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269 \
  --config <new frozen config> --out <new exclusive evidence directory> \
  --live --authorized-usd 2
```

The runner repeats the local check and the authentication check before setup; either failure stops the run with no dispatch. Immediately afterwards, record `sha256(<out>/public-key.json)` outside the evidence directory. Optionally remove the Keychain item: `security delete-generic-password -a "$USER" -s actenon-airlock-live`.

## Reading a failure

The signed receipt now carries `http_status` and, on exact allowlist match only, `provider_error_code`/`provider_error_type` for any non-200 reply, plus the observatory record for streamed replies. The contained agent sees only Airlock's fixed error. Reserved exposure is not a provider bill; reconcile billing separately.
