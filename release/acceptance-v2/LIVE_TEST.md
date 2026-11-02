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
   repository with nothing else in it. The test refuses a public repository, and one with
   more than 5 commits on that branch.
2. Create a fine-grained token limited to that one repository, with Contents read and
   write and Metadata read. Give it a one-day expiry.

## Run it

You need the compute image, which `airlock demo` builds. Then run this from a source
checkout, with Airlock installed:

```bash
GITHUB_TOKEN=YOUR_TOKEN python acceptance/live-github/run.py --repo OWNER/REPO --out ~/airlock-live-test --confirm-live-write
```

A fixed script makes the change in Protected Mode, because this test measures the path to
the provider and not a model. The script tests, reviews, approves, publishes, settles by
readback, retries, and checks the result on a separate read-only client.

## Pass criteria

The command exits 0 only if every check passes:

* The file did not exist before.
* The publish returned `DISPATCHED_UNCONFIRMED`, and readback then confirmed it.
* No effect is left unresolved.
* The bytes on GitHub are the exact bytes of the captured patch.
* The retry was refused.
* The branch has exactly one new commit.
* The token appears nowhere in `.airlock`.

`--synthetic` runs the same steps against the synthetic provider, with no account and no
network. It passes today, and it is not a live result.

## Clean up

Revoke the token and delete the repository. Keep `summary.json` and the `evidence` folder
from `~/airlock-live-test`. They hold the signed receipts and the public key, and no secret.
