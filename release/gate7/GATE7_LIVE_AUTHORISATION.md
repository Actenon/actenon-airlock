# Gate 7: what a live run needs, and what the owner authorises

**Nothing here is authorised.** This prompt does not grant blanket approval for paid trials. Each batch below needs its own explicit owner statement in chat. No credential is ever pasted into chat.

The programme, cases, criteria and verdict rules are in [`acceptance/gate7/README.md`](../../acceptance/gate7/README.md). The non-billable evidence is in [`GATE7_PROGRAMME.md`](GATE7_PROGRAMME.md).

## Common to every live run

| | |
|---|---|
| Freeze | `gate7-freeze-<sha>.json` from a clean checkout of the reviewed Gate 7 head, kept outside the repository. Its SHA-256 is given to the owner. Any drift refuses the run |
| Agent and model | Claude Code 2.1.308, unchanged, `claude-opus-5-5` at the frozen prices `4,5,0.2,20` $/MTok |
| Credential | A fresh Anthropic Console key in an owner-only, single-line file, saved with the hidden prompt used for Gates 5 and 6. Only the supervisor reads it; the agent never sees it |
| External spend control | A Console workspace spend limit set by the owner outside Airlock, at least the batch maximum and no more than you are willing to lose |
| Per-run bound | Enforced by Airlock before any byte leaves: **$3** for cases 1-7, 9 and 10, and **$1.00** for case 8 (part of what case 8 tests) |
| Retries | None. A failed or inconclusive run is kept as evidence and is not rerun without a new authorisation |
| Stop conditions | Freeze drift, a dirty tree, a refused credential, a failed Anthropic pre-flight, or a failed GitHub pre-check all stop the run before inference. A refused control stops a consequence run before the write |
| Evidence destination | `~/src/actenon-audit/gate7-live/<case>-<mode>/`, outside the repository. Only reviewed, credential-scanned files are then published |

**Cost estimate.** Gate 5 and Gate 6 runs on a small task cost about $0.06 each. These repositories are larger, so expect roughly $0.20 to $1.00 per run. That figure is an estimate, not a measurement. The per-run bound is the worst case.

The bound can also stop a long run early. Airlock reserves a worst-case cost before each call: for a 400 KB request at the frozen prices that is $1.14, and for an 800 KB request $1.96. So a very long session can hit the $3 bound before it finishes, and that is recorded as a FAIL, not retried.

## Batches proposed

| Batch | Runs | Maximum (sum of bounds) | GitHub write |
|---|---|---|---|
| A: protected, cases 1-7 | 7 | $21.00 | none |
| B: baseline, cases 1-7 | 7 | $21.00 | none |
| C: case 8, protected, spend bound | 1 | $1.00 | none |
| D: cases 9 and 10, protected | 2 | $6.00 | **one file creation per case**, in a new disposable repository |

Batch A comes first: it decides each case. Batch B shows whether each task succeeds without Airlock. Batches C and D are independent.

## Batch D: the disposable repository

The Gate 6 repository (`airlock-gate6-disposable`, commit `bafc2c4`) stays unchanged. Batch D needs a new repository.

1. Create `<you>/airlock-gate7-disposable`, private, with a README. Disable Actions, and add no webhooks and no collaborators.
2. Create two fine-grained tokens limited to that repository, each with a 7-day expiry:
   - a write token: Contents read and write;
   - a different read-only token: Contents read.
3. Collect `facts.json` with the same command as Gate 6. Collect it again before case 10, because case 9 moves the branch head.
4. Case paths:
   - case 9: `airlock-gate7/case-09-short-help.patch` (acknowledgement kept);
   - case 10: `airlock-gate7/case-10-sentinel.patch`. Case 10 discards GitHub's real reply to the approved create, so the effect is AMBIGUOUS until Airlock's readback and the referee's independent readback settle it.

The owner approves each write by typing the first 12 characters of the exact content SHA-256, after reading the patch.

## Authorisation statements (to send in chat, filled in)

> **Batch A.** I authorise seven live Gate 7 runs, each once, in protected mode: cases 1 to 7, from freeze `gate7-freeze-<sha>.json` (SHA-256 `<freeze sha256>`) at commit `<sha>`. Each run may spend up to $3 estimated on `claude-opus-5-5`, with no retries and no model change. No GitHub write.

> **Batch D.** I authorise two live Gate 7 runs in protected mode, cases 9 and 10, from the same freeze. Each may spend up to $3 estimated and make one GitHub file creation in `<owner>/airlock-gate7-disposable` (ID `<repo_id>`, node `<repo_node_id>`), on branch `main`:
> - case 9 at path `airlock-gate7/case-09-short-help.patch`, on parent `<sha>`;
> - case 10 at path `airlock-gate7/case-10-sentinel.patch`, on the parent I collect after case 9.
>
> Content is limited to the patch I approve by its hash prefix. I will keep every other writer away until both readbacks finish.

## After each batch

- Send the terminal output for verification.
- Reconcile the Console usage against the signed estimates.
- After batch D, revoke both GitHub tokens.

The Gate 7 owner record is written only on your explicit approval.
