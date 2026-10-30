# Live disposable GitHub test (owner-run)

**Status: prepared, not run.** It makes one real write to GitHub, so it needs the owner's
authorization. Everything up to this point used a synthetic provider. A live pass is
required before Release ready, and it does not change any earlier result.

## What it proves

That the same reviewed creation works against real GitHub: exact bytes, one write,
a credential held only by the supervisor, and an independent readback that settles the
effect. It does not prove anything about other repositories or providers.

## Before you start

1. Create a new private repository with one commit on a branch named `review`. Use a
   repository with nothing else in it, and delete it afterwards.
2. Create a fine-grained token limited to that one repository, with Contents read and
   write and Metadata read. Give it a one-day expiry.
3. Finish steps 1 to 7 of the [golden path](../../docs/golden-path.md), so you have a
   candidate that passed `airlock verify-candidate`.

## Run it

Collect the repository facts:

```bash
gh api repos/OWNER/REPO --jq '{id, node_id}'
```

```bash
gh api repos/OWNER/REPO/commits/review --jq .sha
```

Propose the creation:

```bash
airlock review-candidate --candidate SHA256 --output reviewed-create.json \
  --path-in-repo patches/fix.patch --message "Publish the reviewed fix" \
  --repo-id ID --repo-node-id NODE_ID --owner OWNER --repo REPO \
  --branch review --parent PARENT_SHA
```

Read `reviewed-create.json`, then approve it:

```bash
airlock init --approve --github-create reviewed-create.json \
  --reconciler-key ~/.config/airlock/operator.key \
  --credential GITHUB_TOKEN=https://api.github.com
```

Publish with the token in the supervisor's environment only. Do not put it in a file
inside the project.

```bash
GITHUB_TOKEN=YOUR_TOKEN airlock publish --candidate SHA256
```

The expected result is `DISPATCHED_UNCONFIRMED`. Settle it by reading back:

```bash
GITHUB_TOKEN=YOUR_TOKEN airlock reconcile effect_ID --github-readback \
  --operator-key ~/.config/airlock/operator.key
```

Retry the publication to confirm it is refused and that no second commit appears:

```bash
GITHUB_TOKEN=YOUR_TOKEN airlock publish --candidate SHA256
```

```bash
gh api repos/OWNER/REPO/commits?sha=review --jq 'length'
```

The commit count should be exactly one higher than before you published.

## Pass criteria

* The reconcile output says `COMMITTED`.
* `airlock status` shows `COMMITTED: 1` under independently observed, and no unresolved
  effects.
* The file on GitHub has the same SHA-256 as the candidate patch.
* The retry was refused and added no commit.
* The token appears nowhere in `.airlock` or the agent log.

## Clean up

Revoke the token and delete the repository. Keep `.airlock/local/receipts.jsonl` and
`public-key.json` as the evidence.
