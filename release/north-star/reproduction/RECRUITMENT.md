# Recruiting the two item-9 operators (criteria; nobody has been contacted)

Release-bar item 9 needs **two** independent operators on fresh machines. This file fixes, in
advance, who counts and what counts. Recruiting anyone needs the owner's separate approval.

## Who counts

All of these must hold:

1. A human. Not Claude, Codex or any other agent, and not a script.
2. Did not write or review Actenon code, and has no access to Actenon's private material.
3. Not the same person as the other operator, and not the owner running the harness twice.
4. Uses a **fresh supported machine**: a new VM or cloud instance, or a machine wiped and set up
   for the run, with no Actenon software, state, images or caches before starting. Their own
   everyday laptop does **not** count unless it is newly set up.
5. Linux x86_64 or macOS arm64, as `OPERATOR_GUIDE.md` lists. At least one of each platform is
   preferred, but not required.
6. Runs the frozen pack (commit and `expected.json` hash given by the owner) without help from
   Actenon during the run.

Adoption Trial V1 participants may also serve as operators, but only if they meet all of the
above. Completing the V1 demo does not by itself count.

## What counts as a successful reproduction

One operator's reproduction **succeeds** when:

- every step of `report.json` has exit 0, apart from image IDs (NON-REPRODUCIBLE, expected);
- the operator's `OPERATOR_RECORD.md` confirms independence, a fresh machine and no help.

Item 9 needs two successful reproductions **bound to the exact release candidate** the gate
evaluates. Because item 9 is release-level, that is the commit whose artifacts are published
(item 8). Runs against an earlier candidate are useful rehearsal, but cannot be the item-9 record.

An ENVIRONMENT failure does not count as a reproduction, nor against the product; recruit
another operator. A MISMATCH fails that reproduction and is a finding to investigate.

## Cost and consent

- **Cost:** the reproduction needs no paid service. Operators need a machine, Docker and network
  access to public registries. If an operator rents a VM, the owner decides whether to reimburse
  it, before recruiting.
- **Consent:** the operator chooses what to send, and is told that `report.json` and `results/`
  contain their OS and tool versions. Results are used only to decide item 9, and are kept under
  the same retention rules as the adoption trial, unless the owner sets others before
  recruiting.

## Owner record

Only after reviewing both operators' evidence may the owner write
`release/bar-records/item-9.json`. Its `candidate_sha` must be the evaluated release commit, and
its `evidence_path` and `evidence_sha256` must name a committed bundle of both records and
reports. The release gate never infers this record.
