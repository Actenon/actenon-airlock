# Authenticated operator reconciliation

The real Permit ledger and Kernel-backed HTTP broker are under test. Airlock
consumes merged Permit 2074cde4 (state/expiry binding and atomic ledger migration), Kernel 9dd6af89,
Protocol 3442bf3c and Scan ee971b43. Final validation uses these immutable pins,
not the temporary editable Permit candidate used for early falsification.

The first PR CI exposed a real concurrent schema migration race: Python 3.11
failed with `duplicate column name: failure_code` in the existing two-process
effect test. Permit PR #31 serializes inspection and schema changes in one
write transaction, with rollback on failure. Its preserved CI log and regression
evidence are in Permit `docs/evidence/atomic-ledger-migration`. This pin consumes
that merged repair; the Airlock concurrent test remains unchanged.

`before-contract.xml` records the previously missing product workflow (module
unavailable), not an execution attack. `before-rename.xml` records an actual
approved os.rename moving an external operator key into a readable project
alias. The direct link and symlink attempts already failed that run.
`before-tree-link.xml` records an actual approved copytree using a custom copy
function to hardlink the operator key instead of its input; the old worker
returned success. The fixed worker refuses links even inside tree scopes.
No failing attack was weakened: both require no alias, no extra hard link,
and a signed refusal. Ordinary in-project rename still works.

After: 142 integrated tests passed, zero skips; Ruff and formatting passed;
dependency doctor passed. Cases cover unsigned/foreign signers, tampered and
valid-but-mismatched signatures, changed authority, domain confusion, expiry,
stale review, conflicting independent processes, old observation replay after
a fresh retry, mutable provider objects, separate-process CLI application
without runtime secrets or observer private key, and journal failures.

The launcher also retains its documented refusal exit code when shutil wraps
a denied operation in its own exception. Receipts independently verify nested
observer signatures and their historical signed approval at settlement time,
even after expiry/key rotation, without the private key or ledger. A valid
outer receipt signature cannot hide invalid observer evidence.

This authenticates a separately authorized observer's assertion; it does not
independently establish remote finality. No provider-specific finality adapter,
PostgreSQL cross-host ownership, hostile-code OS containment, exact-action
execution approval, or complete G1–G40 acceptance is claimed. Same-user hostile
code/native or approved uncontained subprocesses require real isolated custody
and Protected Mode. No package/tag/release was published.
