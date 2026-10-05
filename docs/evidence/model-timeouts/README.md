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


[Fourth run 37287365835](https://github.com/Actenon/actenon-airlock/actions/runs/37287365835)
at head `f656a30501ee7ebdfccb838149989edebeac8119` completed five real requests
with the pinned 7b model. Eleven signed receipts verify. The model repaired pipe
draining and tail output, but timeout still raised `subprocess.TimeoutExpired`
instead of the required built-in `TimeoutError`; invalid diff hunks left
unreachable copies of the old code. The last 1536-token response produced no
further applied change. The engineering gate failed and no PASS is claimed.
Selected original evidence is preserved in `fourth-real-agent-failure/`.

The next run keeps the same model, output bound, full external source, public
agent API and every regression assertion. The task now includes the actual
unchanged tests and requires diff context copied from the current source.
A no-change response is recorded as an unsuccessful attempt instead of aborting
before its diagnostics can be preserved. Only the external agent's explicit
`improve.txt` and `diff_errors.txt` public transcript files are exported to explain
edit failures; no complete workspace, private authority state or secrets are exported.


[Fifth run 37290106747](https://github.com/Actenon/actenon-airlock/actions/runs/37290106747)
at `c6721f6b6e0ddf898b22647119ef6cb7ed8ea817` completed three real requests,
with seven verified signed receipts. The exported agent transcript shows an
unindented `with` body, followed by two irrelevant repeated assertion edits.
Every unchanged regression run failed collection. No model timeout or truncation
caused this failure. The original transcript, generated source and test results
are retained in `fifth-real-agent-failure/`.

The amended evidence-defined goal requires a matched unprotected baseline before
protected utility can be scored. None of these five historical runs had one.
They remain failed protected runs; they do not prove that Airlock caused, or had
no effect on, the task failure. The candidate now freezes source/task/tests/model,
image and resource hashes before both phases, requires the same unprotected
workload to pass first, and preserves baseline failure instead of continuing to
a protected PASS claim. The model, task and regression assertions are unchanged.


[First matched baseline 37293241687](https://github.com/Actenon/actenon-airlock/actions/runs/37293241687)
at `48e7484227a78a6e9684da0441435c328a4baa15` ran the frozen full agent,
model, task and unchanged tests directly against the disposable local provider.
All three model edit attempts failed with the same indentation error. No compile,
shell-compute or commit milestone was reached. The tests remained byte-identical.
The protected phase was correctly skipped. The raw preregistration, actual
container resource settings, transcript, generated code and results are preserved
in `first-matched-baseline-failure/`. Configuration SHA-256:
`069e3d085b37d278c1106677c6b219d61f4bb7390d2a02c51c36c27cc7a76dd9`.

The next preregistered configuration changes only model capacity to official
[`qwen2.5-coder:14b`](https://ollama.com/library/qwen2.5-coder:14b), manifest
`9ec8897f747e246e970bc5cfdda85d22f1123dc2e3d34978a010a75968716849`.
Its exact public layers total 8,988,123,810 bytes. The observed preceding runner
had 15.6 GiB total memory and 14.3 GiB available when loading the model. A new
preflight records actual memory and disk after dependency/runtime preparation,
and refuses model download unless at least 12 GiB memory and the model bytes
plus 3 GiB disk remain available. This is capacity admission, not proof that the
model will solve the task or meet the unchanged timeout. The source, task, system
prompts, tools, tests, temperature, token bound, attempt count and phase limits
are unchanged. Baseline must pass before protection is scored.

[Second matched baseline 37295234658](https://github.com/Actenon/actenon-airlock/actions/runs/37295234658)
at `3da414c6719c406ad44dd91d115a6d289484a072` failed after 30 minutes and
31 seconds. The runner admitted the pinned 14b model with 13.68 GiB available
memory and 82.97 GiB free disk. Seven real responses completed within the existing
timeout, without observed context or output truncation. The first response
invented prior code and inconsistent indentation; the unchanged external diff
salvager applied some hunks, then refinements repeatedly inserted statements into
incorrect locations. All three unchanged-test attempts failed collection with
`IndentationError`. Compile, shell computation and local commit were not reached.
The protected phase was correctly skipped. Capacity and model completion do not
establish useful task execution. The complete selected transcript, diff errors,
generated source, actual capacity, preregistration and results are preserved in
`second-matched-baseline-failure/`, with a file checksum manifest. Configuration:
`63d5ac827920707a1935317d65ece1b784b39c32f3c354cfdf0483357b84f2dd`.

The next configuration changes only the public preprompt setting. The default
prompts demand a long architecture response and extra package files; the reviewed
replacement gives generic existing-code and precise unified-diff instructions.
It supplies no solution code or repair algorithm. `SimpleAgent.with_default_config`
accepts the `PrepromptsHolder` object directly; both upstream fallback sites retain
that truthy object, and the original prompt renderer substitutes `FILE_FORMAT`
exactly once. All four files are hashed in the matched preregistration and copied
identically to both phases. The task expression, full source revision, regression
SHA, model and resource limits remain unchanged. This setting still requires a
new successful baseline and protected result at the integrated candidate revision.
