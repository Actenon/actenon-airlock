# Codex CLI independent integration — in progress, 2026-10-31

Branch: codex/airlock-codex-cli-north-star. Base: 9ccfa818752ac61e37fb2a20c51ab4e7261652a3.
This coherent candidate contains PR17 b3ad30d843afaf780d8370922b5f23f95e50b040 and
PR18 17188d3dfb6fec24bb7477acc60a8591de8c703e. Supporting dependency SHAs unchanged.

Official unchanged Codex 0.166.0, source 6ff1e1ca3b30fc8b914720681fcf5fe62e95f856;
architecture tarball hashes in containers/codex-cli/upstream.json. Direct-tool
GPT-5.5 interface; Code Mode models are unsupported by this initial contract.

Implemented Responses contract, exact pre-authorization output cap, no stored
conversation, local client tools, checked usage, held uncertainty and host credential
separation. Product path: setup --agent codex-cli, work, capture, verify-candidate,
review-candidate, publish, reconcile, checkpoint, verify-evidence.

Real binary scripted tool loop passed: read, failing tests, edit, passing tests,
continued inference. Scripted decisions are NOT real-model acceptance. Docker
transport controls and the approved/synthetic consequence journey pass. The first
full suite has one test expectation failure (safe exception vs returned refusal),
corrected and reverified independently; final full-suite/CI verification pending.

Matched token-bucket scripted rehearsals pass 3 visible and 4 hidden tests. The
network-enabled attack delivered its synthetic canary; Protected Mode delivered
none to the same working owned endpoint. These are harness-selected attacks.

An owned negative control reproduced host-file symlink following in the reused
acceptance scorer. It now uses the existing O_NOFOLLOW snapshot routine; permanent
negative and positive regressions pass. Frozen historical results are untouched.

No live model call, live GitHub mutation, publication, merge or tag performed.
Live acceptance remains NOT RUN pending explicit budget approval and a legitimate
supervisor-held API key. No ChatGPT token/cache has been read or copied.
Historical gates and Aider/Claude/frozen real-model evidence are unchanged.
