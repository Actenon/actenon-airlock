# Real-model timeout evidence

Clean Linux run [37245194446](https://github.com/Actenon/actenon-airlock/actions/runs/37245194446)
installed the pinned, complete gpt-engineer source/dependencies and hash-verified
Ollama/qwen3:4b runtime. The unchanged external execution helper failed its
regression. The actual model began processing the task but the HTTP read phase
exceeded Airlock's fixed 30 seconds. The signed receipt records AMBIGUOUS with
`execution_occurred: null`; the effect remains held. This is a failed useful-agent
acceptance, not a claim that the provider did nothing.

The signed model profile may now narrow a read-phase timeout to an integer from
1–600 seconds. Legacy profiles keep 30 seconds. `airlock init --model …
--model-read-timeout 600 --approve` makes the change visible and reviewed;
increases are authority-review expansions. Neither agent payloads nor headers
control the supervisor timeout. Other HTTP stays at 30 seconds. The relay wait
allows bounded inference to return; it cannot authorize a request.

This is a timeout for an HTTP phase, not an overall job deadline. Outcome,
reservation, budget hold, model/output limits, credentials and proof verification
are unchanged. A simulated lost response after dispatch still records AMBIGUOUS
and refuses a second transport call. Targeted tests: 50 passed, one documented
separate-container skip. The real-model rerun remains required.

## Second real failure and bounded coding configuration

[Run 37282985403](https://github.com/Actenon/actenon-airlock/actions/runs/37282985403)
at head `01e7de5961885d2018517ebf9b691b8242c6b93b` failed again after the
reviewed 600-second read phase. Ollama generated 3023 tokens, shifted its 4096-token
context, and was canceled before a completed response. The second signed public
receipt set is retained here. It again reports AMBIGUOUS/null and holds the effect.
Eight core checks passed; the useful external coding acceptance did not pass.

A diagnostic against the same cached model also produced reasoning text with
the documented `reasoning_effort: none` setting. Its pinned template prefills an
open `<think>` block. This diagnostic is not Protected Mode acceptance evidence.
No broader model API allowance is added for this failed configuration.

The next real run uses official `qwen2.5-coder:3b`, manifest SHA-256
`f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225`,
1536 reviewed output tokens, and an 8192-token local server context. The unchanged
gpt-engineer public API may receive at most three rounds of actual test feedback.
No supplied answer, fixture model, paid provider, rewritten agent implementation,
test weakening or extra execution authority is used. The task still fixes its
real execution helper; original deadlock, timeout and output regressions remain.
The same environment also attempts direct model access, protected host/key paths,
fake policy/environment/cwd replacement and the existing bypass matrix.

Sources: [Ollama API](https://docs.ollama.com/api/openai-compatibility),
[pinned API implementation](https://github.com/ollama/ollama/blob/v0.32.9/openai/openai.go),
[official coding model](https://ollama.com/library/qwen2.5-coder:3b).
This configuration still requires a successful real CI run before merging #13.

[Third run 37285768855](https://github.com/Actenon/actenon-airlock/actions/runs/37285768855)
completed seven real model requests and independently verified 15 signed receipts.
No inference timed out. The unchanged regression still failed after all three
actual agent edit attempts: a deadlock remained, then indentation errors. Model
completion is not engineering-task success; #13 remains unmerged. Public generated
code, each unchanged-test result and receipts are preserved in a separate folder.
The next acceptance configuration uses official `qwen2.5-coder:7b`, manifest
`dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`,
with the same 1536-token bound, public agent API, regressions and containment.
