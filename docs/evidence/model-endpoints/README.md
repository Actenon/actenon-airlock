# Reviewed model endpoints

Custom OpenAI-compatible endpoints previously bypassed the model guard because
it recognized only the default provider URLs. Changing a reviewed endpoint also
did not appear as an authority expansion. `before.xml` preserves six failing
regressions; `after.xml` records 34 passing targeted tests and the documented
container-only skip. Container acceptance runs separately in CI.

The signed model profile now narrows an existing, exact Scan HTTP power to an
endpoint, text-inference format, model list and output-token limit. It cannot
create a missing power. Scan's native SDK route evidence supplies the format;
unsupported SDK operations are denied before transport or credential release.
An endpoint change requires review even when the source powers are unchanged.
HTTPS and literal loopback HTTP endpoints are supported; query-bearing model
endpoints and HTTP DNS targets are refused.

For a project whose native Scan evidence already contains the endpoint:

```sh
airlock init --approve --model qwen3:4b \
  --model-endpoint http://127.0.0.1:11434/v1/chat/completions \
  --model-max-tokens 4096
```

The contained SDK relay uses a public, read-only routing map. The host supervisor
independently verifies the actual endpoint; changing agent configuration cannot
widen authority. Tokenizer assets may be prepared in the compute image under
`/opt/airlock/tiktoken`, without granting download authority during execution.

These tests establish endpoint binding, not a successful external coding-agent
workflow. Real-agent acceptance and the public-artifact release gates remain
open. Streaming responses remain AMBIGUOUS unless the boundary observes a
supported complete inference result.
