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
