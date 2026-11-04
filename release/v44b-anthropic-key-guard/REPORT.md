# Anthropic-key guard for the OpenAI credential pre-flight

Found while preparing the V4.4b live trial: an Anthropic API key (`sk-ant-…`) satisfies the pre-flight's generic `sk-` prefix and charset checks. The live runner would therefore have sent it to OpenAI's model-lookup authentication request. OpenAI would have rejected it with no inference, but another provider's credential would still have been disclosed.

- Regression first (`79911b6`): **5 expected failures** (`before-guard.txt`). These were the local check for API, OAuth and upper-case forms, the live runner reaching past the local check, and `authenticate()` accepting the key.
- Fix (`380bcc6`): `format_problems` reports `anthropic-key` for any case of the `sk-ant-` prefix, and `supervisor_credential` refuses with a fixed message that never contains the value ("this is an Anthropic API key; this run needs an OpenAI API key. Nothing was sent"). `authenticate()` independently refuses, so no caller can send such a key to OpenAI.
- After: the 30 pre-flight tests pass. The full Airlock suite with real Docker passes: **2,053 passed, 0 failed, 0 skipped**. Lint and format (CI scope), wheel build, clean install and `doctor` all pass. The real runner refuses a synthetic Anthropic-format key before any Docker or network step.

Nothing else changed. Sanitising, credential isolation, authority, budgets and accounting are untouched. No paid inference occurred. The live trial still requires an **OpenAI** API key.
