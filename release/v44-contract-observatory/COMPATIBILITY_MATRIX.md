# Response compatibility matrix v1 — 2026-11-03

This is an inventory and semantic review, not a permission generator. `accepted` means the existing inbound allowlist admits the property; it does **not** imply full value validation. Restricted and unsupported forms are explicit. The V4.4 repair expands only `image`. The table exposes inherited semantic gaps rather than silently tightening or broadening them.

Source: [official retrieve reference](https://developers.openai.com/api/reference/resources/responses/methods/retrieve), exact installed OpenAI SDK 2.54.0, and Airlock validators. JSON records exact inventories, SDK annotations and source hashes. `output_text` is documented as SDK-only convenience. SDK declaration and current API documentation are distinct evidence.

V4 has no recovered field-name set. V4.1 identifies presence_penalty, frequency_penalty and tool_usage by signed hashes. V4.2 identifies tools validation, not the nested offending properties. V4.3 identifies image, not its value. Other rows are not claimed as reconstructed live contents.

| Field | Airlock / SDK / docs | Classification; relevance | Actual acceptance / limitation |
|---|---|---|---|
| `access_programs` | yes / no / yes | restricted; authority, state | Absent/null only; no access-program grant. |
| `background` | yes / yes / yes | restricted; state, completion | Absent/null/false; inherited equality check also admits numeric zero. No background request authority. |
| `completed_at` | yes / yes / yes | accepted; completion, descriptive | Admitted metadata; timestamp value is not a completion proof and is not independently type-validated. |
| `conversation` | yes / yes / yes | restricted; state | Absent/null only. Populated conversation IDs remain unsupported. |
| `created_at` | yes / yes / yes | accepted; descriptive | Admitted timestamp metadata, not independently type-validated or used as authority. |
| `error` | yes / yes / yes | restricted; completion | Must be absent/null for a confirmed result; private error text is never copied to diagnostics. |
| `frequency_penalty` | yes / no / no | restricted; generation | Absent/null or exact int/float zero; bool, nonfinite and nonzero refused. Live name proven; response enumeration absent from pinned SDK and current retrieve reference. |
| `id` | yes / yes / yes | restricted; identity | Nonempty string; same response identity across lifecycle snapshots. |
| `image` | yes / no / yes | restricted; descriptive, generation | Omit or exact object with required context_compression enabled/disabled; no null, auto, extras or changed effective policy. No image-input/output/tool grant. |
| `incomplete_details` | yes / yes / yes | restricted; completion | Must be absent/null for confirmation; incomplete outcomes retain reservations. |
| `instructions` | yes / yes / yes | accepted; descriptive | Admitted response echo; no inbound value/type parity check. Never used to rewrite the approved request or supervisor policy. |
| `max_output_tokens` | yes / yes / yes | restricted; billing, generation | Absent/null or exact integer equal to dispatched request cap; actual token usage independently bounded. |
| `max_tool_calls` | yes / yes / yes | accepted; authority, billing | Admitted echo, no independent value validation; cannot grant hosted tools. Hosted activity/output checks remain separate. |
| `metadata` | yes / yes / yes | accepted; descriptive | Admitted opaque response metadata, not independently type-validated; values are not copied into receipts. |
| `model` | yes / yes / yes | restricted; identity, billing | Exact equality with the signed approved model at every snapshot. |
| `moderation` | yes / yes / yes | restricted; generation | Absent/null only; no moderated-completions feature was requested. Populated results/errors unsupported. |
| `object` | yes / yes / yes | restricted; identity | Exactly response. |
| `output` | yes / yes / yes | restricted; completion, authority, billing | Only reviewed text/reasoning/local function/custom outputs; typed IDs/calls, complete stream parity. No hosted operations or generated images. |
| `output_text` | no / no / yes | unsupported; descriptive | SDK-only convenience property, not a declared SDK model field or accepted wire extension; use validated output items. |
| `parallel_tool_calls` | yes / yes / yes | accepted; generation, authority | Admitted echo, not independently type/parity-validated. Each local consequence still requires its own authority. |
| `presence_penalty` | yes / no / no | restricted; generation | Absent/null or exact int/float zero; bool, nonfinite and nonzero refused. No outbound penalty setting is authorized. |
| `previous_response_id` | yes / yes / yes | restricted; state | Absent/null only; no provider-held history chaining. |
| `prompt` | yes / yes / yes | accepted; state, generation | Legacy admitted echo without nested validation; no outbound stored-prompt reference is authorized or resolved. This remains a semantic-validation limitation, not new authority. |
| `prompt_cache_diagnostics` | no / no / yes | unsupported; state, descriptive | Every value, including null, deliberately unsupported. Comparison was not requested; counts are not billing usage. |
| `prompt_cache_key` | yes / yes / yes | accepted; state, billing | Admitted echo without parity validation; cache routing cannot change signed authority, replay identity or usage settlement. |
| `prompt_cache_options` | yes / yes / yes | restricted; state, billing | Absent/null only under pinned SDK nullable representation. Current populated options concern GPT-5.6+; not authorized for this GPT-5.5 profile. |
| `prompt_cache_retention` | yes / yes / yes | accepted; state, billing | Legacy admitted echo without enum/parity validation; cannot alter outbound request. Extended caching semantics require separate contract review. |
| `reasoning` | yes / yes / yes | accepted; generation | Admitted configuration echo without nested parity checks. Reasoning output content follows separate output validation and is never logged. |
| `safety_identifier` | yes / yes / yes | accepted; descriptive | Admitted echo, no independent value/type validation, never copied into diagnostic records. |
| `service_tier` | yes / yes / yes | accepted; billing | Legacy admitted echo without tier/parity validation; does not change the reviewed accounting price schedule. Actual provider billing is not established. |
| `status` | yes / yes / yes | restricted; completion | Created/progress must be in_progress; only internally consistent terminal completed can confirm. |
| `store` | yes / no / no | restricted; state | Absent/null/false; inherited equality check also admits numeric zero. No storage request authority. Response declaration absent from pinned SDK/current retrieve reference. |
| `temperature` | yes / yes / yes | accepted; generation | Legacy admitted echo without range/parity validation; no additional supervisor authority. |
| `text` | yes / yes / yes | accepted; generation | Admitted format configuration echo without nested parity checks; actual output still requires reviewed text structure. |
| `tool_choice` | yes / yes / yes | accepted; authority, generation | Admitted selection echo without independent nested parity checks; returned tool inventory and actual calls remain separately validated. |
| `tool_usage` | yes / no / yes | restricted; authority, billing | Absent or exact reviewed families image_gen/web_search, required members and exact integer-zero counters; optional detail omissions allowed. Unknown categories/nonzero counts remain unpriced and unconfirmed. |
| `tools` | yes / yes / yes | restricted; authority, billing | Omission is no echo; otherwise exact approved function/custom/namespace inventory and definitions with reviewed direct-only defaults. Boolean strictness resolution must remain consistent. |
| `top_logprobs` | yes / yes / yes | accepted; generation | Legacy admitted echo without type/range/parity validation; unsupported output extensions still fail output validation. |
| `top_p` | yes / yes / yes | accepted; generation | Legacy admitted echo without type/range/parity validation; no new execution authority. |
| `truncation` | yes / yes / yes | accepted; generation | Legacy admitted echo without enum/parity validation; incomplete responses cannot confirm. |
| `usage` | yes / yes / yes | restricted; billing, completion | Exact reviewed base-token schema, nonnegative integers, sums/bounds/cache consistency. Cache-write count must be zero; unknown financial categories refused. |
| `user` | yes / yes / yes | accepted; descriptive | Legacy admitted identity echo, not independently type-validated; not copied into diagnostics. |

Arbitrary additional fields remain unsupported (unknown/insufficiently documented). Fixed public names are diagnostic identifiers only. Inherited opaque echoes such as prompt, retention and service_tier deserve separate semantic review before expanding supported request features or treating their values as provider guarantees. Their admission never authorizes state, tool execution or a different price schedule.
