# One reviewed GitHub consequence

This development candidate lets a protected agent create one precisely reviewed file through
GitHub's Contents API. It does not authorize issue writes, repository deletion, updates to an
existing file, arbitrary GitHub requests or secret egress. Scan supplies the named power
`github.contents.write`; Airlock narrows that power to the exact provider operation. Permit
owns the finite grant and durable effect reservation; Kernel independently verifies and claims
the proof before the supervisor can obtain a credential or contact GitHub.

## Review the exact creation

Prepare the patch or other UTF-8/binary file locally, inspect its bytes, and compute its SHA-256.
Obtain the disposable repository's numeric ID, node ID and current target branch commit on the
trusted operator side. The source must contain the exact GitHub Contents URL as a resolved
Scan power. A profile cannot manufacture a missing source power.

The following is a schema example, not an authorized live target or runnable acceptance claim:

```json
{
  "schema": "actenon-airlock/github-create/v1",
  "exclusive_writer": true,
  "credential_name": "GITHUB_TOKEN",
  "review": {
    "repo_id": 123,
    "repo_node_id": "R_example",
    "owner": "example",
    "repo": "disposable",
    "branch": "review",
    "path": "patches/fix.patch",
    "message": "Reviewed coding-agent patch",
    "content_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "expected_parent_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

Use a repository-scoped credential held only by the supervisor, with access to the disposable
repository and only the permissions needed for this operation. Keep other writers and automation
away from the target branch during creation and readback. Airlock cannot infer or enforce those
external GitHub account conditions; the reviewer explicitly accepts them in this profile.

```sh
airlock init --github-create reviewed-create.json --reconciler-key ~/.config/airlock/operator.key
airlock init --approve --github-create reviewed-create.json --reconciler-key ~/.config/airlock/operator.key
airlock run --protected -- python3 agent.py
```

The first command proposes; the second signs the reviewed authority. The reconciler key is
outside the agent project and is not mounted in the container. A model profile, when needed,
is reviewed separately as described in [Protected Mode](protected-mode.md).

The agent's PUT body must contain exactly `message`, canonical base64 `content`, and `branch`.
Content is bounded to 64 KiB. Existing-file `sha`, additional fields, altered content/message,
another path/branch or a different repository fail closed. Redirects are not followed. The host
fixes the API headers; agent-selected trace headers cannot mint a different logical effect.

Each creation has its own finite Permit grant. The model-only grant has no GitHub authority.
Removing a power from source removes it from runtime authority. Reapproval, a fresh run or a
fresh grant cannot clear ownership of an already claimed logical effect. The profile's parent
commit and exclusive-writer condition are signed review constraints; changing them requires
review but does not reset the effect identity.

CI compares the entire proposed profile to the signed trusted-base approval. A PR cannot
self-approve new content, a new file, changed parent/message or another branch by editing its
own approval. `airlock init --clear-github --approve` removes the profiles.

## Observe before settling

After Kernel claims the effect, the host verifies repository identity, the reviewed branch head
and file absence at that immutable parent commit. A failed preflight proves this callback did
not send the PUT, and records `NOT_EXECUTED`. Its receipt still reports any credential used for
the preflight reads. Once the PUT is attempted, a response or timeout leaves ownership held as
`AMBIGUOUS`; a 201 alone never means `COMMITTED`.

```sh
airlock reconcile effect_<id> --github-readback --operator-key ~/.config/airlock/operator.key
airlock receipts
```

Readback reconstructs the original signed request and selected profile, checks the ledger
binding, then obtains bounded repository, commit and immutable file observations. It requires
the reviewed parent, exactly one added file, exact content/blob, commit message and repository
identity. A recorded 201 commit identifier, when available, must also match. A positive result
produces an observation signed by the separately approved operator key and applies it through
the existing reconciliation checks. Add `--output observation.json` for detached review without
settling; apply with `airlock reconcile effect_<id> --approval observation.json`.

Missing objects, moved branches, conflicts, timeouts, invalid responses or missing credentials
remain `AMBIGUOUS` (exit 4). They produce no settlement envelope, refund or automatic retry.
Readback never sends a PUT. Receipt verification alone does not establish provider truth: the
signature authenticates the authorized observer and the evidence hash.

## Declared limits and evidence

GitHub's Contents create operation has no compare-and-swap on the parent branch commit.
Preflight and creation are separate requests. This profile therefore requires the declared
exclusive-writer condition; it is not safe to claim protection against a concurrent external
writer. Positive readback proves the narrowly specified provider state under that assumption,
not which process caused it. Evidence explicitly records `causal_attribution: not_proven`.
It does not establish billing, arbitrary remote exactly-once execution or cross-host ownership.

The signed authorization receipt includes the exact reviewed creation body, hashes, selected
profile, grant and proof. Bounded readback bodies are stored with owner-only permissions below
`.airlock/local/`. They may contain private code and GitHub user metadata. Headers and exception
messages are not retained; active credential echoes are hash-only. This is private evidence,
not a public export or a general secret-redaction service. Inspect/redact exports before sharing.

Fixture tests exercise real Scan/Permit/Kernel and, separately, actual container isolation. They
do not demonstrate a live GitHub mutation, useful external-agent completion or outside-operator
reproduction. Those acceptance gates remain open until their own evidence is recorded.
