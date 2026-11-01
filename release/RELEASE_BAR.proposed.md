# What a release still needs

**Status: proposed for the owner's decision.** The release gate does not load this file. It changes no frozen requirement: G1-G40, the recovered goal, acceptance v2 and every failed result stand as recorded.

## Why this exists

The release gate cannot reach RELEASE READY, however good the product gets:

* **G1-G27, G39 and G40 have no text.** The individual definitions were not recoverable from any repository, PR, issue, transcript or local store.
* **G28-G38 belong to one frozen programme,** gpt-engineer with `qwen2.5-coder:14b`. All 8 recorded runs failed, and it may not be repeated without a new hypothesis.

Only the owner can resolve that, in one of two ways: commit the verbatim text as `release/G1-G40.frozen.md`, or accept a replacement bar and record the decision. This file proposes that replacement. It holds the product to the recovered goal's sections A-F, which do not depend on the missing text.

## The proposed bar

| # | Requirement | Goal section | Today | What it needs |
|---|---|---|---|---|
| 1 | One candidate holding every supported agent | A | **Done** | Nothing |
| 2 | Exact authority, an enforced boundary and truthful effect ownership | B, C, D | **Done**, in the full suite with real Docker | Nothing |
| 3 | A stranger can see it work, with no key and no cost | F | **Done:** `airlock demo` from a clean wheel in an empty folder | Nothing |
| 4 | One entry point from task to reviewed patch | F | **Done** with real agent binaries and a scripted model | Nothing |
| 5 | A real model does useful work beside a matched baseline, and the attacks run from the same environment | E | **Not run** | Paid inference: $2.00 for the first slice, at most $62.00 in all for Claude Code. Codex is at most $8.00 |
| 6 | One real GitHub write, confirmed by independent readback | E | **Not run.** The test passes against the synthetic provider | The owner's go-ahead, a disposable repository and a token limited to it |
| 7 | Three original repositories and ten agent cases | E | **Not run** | The owner names the repositories. At $2.00 a run with a matched baseline, at most $40.00 |
| 8 | Install from public registries alone | F | **Blocked** | The owner merges the Kernel and Permit candidates and publishes the packages and images |
| 9 | Two independent operators on fresh machines | F | **Blocked** | Two people outside this work. Another agent rerunning the same workspace does not count |
| 10 | The owner accepts this bar, or commits G1-G40 | - | **Open** | One decision |

Items 1-4 are engineering, and they are finished. Items 5-10 need money, a credential, a name or a decision that only the owner can give.

## The shortest route

1. **Item 10:** accept this bar, or amend it.
2. **Item 5, first slice:** one Claude Code journey, capped at $2.00. This is the first time a real model drives the product end to end, so it may find defects no scripted reply can.
3. **Item 6:** the [live GitHub test](acceptance-v2/LIVE_TEST.md). It costs nothing and takes minutes.
4. **Item 5, the rest,** once the first slice's real cost is known.
5. **Item 7.**
6. **Item 8,** so that operators install what users will install.
7. **Item 9.** The [reproduction guide](../acceptance/v2/README.md) is what they follow.

A failure at any step stays in the evidence, and the status stays NOT READY until every row is done.
