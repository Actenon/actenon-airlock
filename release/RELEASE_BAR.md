# Airlock release bar

**Accepted by the owner on 2026-11-01** in place of the unrecoverable G1-G40 text. This is what the release gate checks. Its SHA-256 is pinned in `release/gates.json`, so changing this file needs a reviewed change to both.

It takes effect when it reaches `main`, because the gate reads its rules from there. What is still open is in the [checkpoint](CHECKPOINT.md).

## Why it replaced G1-G40

* **G1-G27, G39 and G40 have no text.** The individual definitions were not recoverable from any repository, PR, issue, transcript or local store.
* **G28-G38 belong to one frozen programme,** gpt-engineer with `qwen2.5-coder:14b`. All 8 recorded runs failed, and it may not be repeated without a new hypothesis.

So the gate could not have reached RELEASE READY, however good the product became. The history stands: every recorded result and failure is kept, the gate still reports G1-G40 as superseded, and acceptance v2 is unchanged. This bar holds the product to the recovered goal's sections A-F, which do not depend on the missing text.

## The bar

| # | Requirement | Goal section | Level | Evidence the gate reads |
|---|---|---|---|---|
| 1 | One candidate holding every supported agent | A | Candidate | CI on the exact commit |
| 2 | Exact authority, an enforced boundary and truthful effect ownership | B, C, D | Candidate | CI on the exact commit |
| 3 | A stranger can see it work, with no key and no cost | F | Candidate | CI on the exact commit |
| 4 | One entry point from task to reviewed patch | F | Candidate | CI on the exact commit |
| 5 | A real model does useful work beside a matched baseline, and the attacks run from the same environment | E | Candidate | Owner record |
| 6 | One real GitHub write, confirmed by independent readback | E | Candidate | Owner record |
| 7 | Three original repositories and ten agent cases | E | Candidate | Owner record |
| 8 | Install from public registries alone | F | Release | PyPI, compared with the locked hashes |
| 9 | Two independent operators on fresh machines. Another agent rerunning the same workspace does not count | F | Release | Owner record |
| 10 | The owner accepts this bar | - | Candidate | This file matching its pin |

Items 1-4 and 8 come from authenticated sources. Their dependency graph must also pass, and a changed goal document blocks everything.

Items 5, 6, 7 and 9 happen where GitHub cannot attest them: on the owner's machine, against a live account, or in someone else's hands. So their evidence is an owner record, reviewed onto `main`.

## Owner records

A record is a file named `release/bar-records/item-N.json`:

```json
{
  "schema": "actenon-airlock/release-bar-record/v1",
  "item": 5,
  "candidate_sha": "the full commit the evidence is about",
  "result": "PASS",
  "evidence_path": "release/bar-records/item-5/programme.json",
  "evidence_sha256": "the SHA-256 of that committed file"
}
```

The gate reads records from its own reviewed checkout, never from the candidate, and they must bind to the exact commit under evaluation. Any later commit needs a new record. A missing record blocks. A `FAIL` result, a wrong commit, an unreadable record or evidence that does not match its hash never passes.

A record says the owner reviewed that evidence. It does not make the evidence true. Keep failed runs in the evidence too.
