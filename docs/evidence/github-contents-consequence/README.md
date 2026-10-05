# GitHub create-only consequence: pure host candidate

Base Airlock source: `48e7484` (exact full SHA in `manifest.json`). No dependency
metadata or broker/grant code is changed here. Root integration is a separate
step. These fixtures are **not live GitHub evidence**.

## Contract and interface

`ReviewedGitHubCreate` is built only from signed, host-reviewed fields: numeric
repository ID, repository node ID, owner/name, existing branch, exact path,
content SHA256, commit message, and expected parent commit SHA. Its `.projection`
and `.effect_descriptor(namespace)` are available before any agent request.
The namespace belongs to trusted durable owner state. Trace/header, grant,
session/proof IDs, JSON formatting, and parent-head changes do not reset that
provider consequence identity. A separately reviewed file path is distinct.

`project_create("PUT", review.contents_url, raw_body, review)` accepts exactly
`message`, `content`, and `branch`. It rejects `sha` updates, author/committer
changes, unknown fields, duplicate members, alternate encoding, URL variants,
workflow files, path ambiguity, and unsupported branch spellings. The resulting
`.body` is the one canonical byte string for authority, proof and dispatch.
`.body_sha256`, `.git_blob_sha1`, `.content_size`, `.action`, and `.resource` are
provided for host integration. Git blob SHA1 is checked alongside SHA256, not
used as a new authorization primitive. The size limit is 64 KiB of file bytes;
request JSON is bounded to 128 KiB and every readback body to 1 MiB.

Scan's real `classify_http` must resolve the exact endpoint to
`github.contents.write`. This module does not issue grants. Existing Airlock
encodes the Scan action/resource/transport tuple into a Permit capability
`airlock.<digest>` and uses target type `tool`. Root integration must preserve
that existing representation when building the Protocol descriptor and Kernel
intent; the default named descriptor here is not a substitute for that bridge.

`validate_preflight(request, repository, branch, absent_contents,
exclusive_writer=True)` checks repository IDs/name, an exact branch-ref observation
at the reviewed parent, and file 404 at that immutable parent. `HostObservation`
objects may only originate from the trusted host transport, with redirects
disabled; the agent cannot supply them.

For readback, fetch `review.branch_commit_url`; then
`validate_commit_observation` verifies exactly one reviewed parent, matching
message and exactly one added file/blob. It returns the SHA to use with
`review.contents_at(sha)`. Pass the independent repo, branch-commit and immutable
contents observations to `confirm_create`. If a 201 response was received,
`received201_commit_sha` must be the validated response's SHA; another matching
commit cannot replace it. A lost acknowledgement can use anchored branch-head
readback only under the same explicit exclusive-writer assumption.

`ProviderConfirmation` returns COMMITTED only for exact anchored file bytes,
blob, path, repository, branch head, parent and message. Other outcomes are
AMBIGUOUS, never an automatic retry/refund. `causal_attribution="not_proven"`
and `observation_kind="anchored_provider_state"` make the scope explicit. The
separate host reconciliation authority must bind the observation hash to the
original effect, reservation and attempt, then sign it. No credentials or raw
provider response bodies are returned by this validator.

## Provider assumptions and limits

GitHub Contents creation has no compare-and-swap parent parameter. Preflight
and readback cannot remove a shared-writer race. Use an explicitly authorized
disposable repository with an exclusive writer and a fine-grained credential
bound to the reviewed repository identity. Without that deployment assumption,
confirmation stays AMBIGUOUS. Renames/transfers to another name or repository
ID/node changes refuse. The transport must check identity before releasing the
credential, refuse redirects, and check identity again for readback. This does
not claim universal causal attribution or provider-wide exactly-once execution.
A subsequent branch move may prevent this conservative branch-head confirmation
and require trusted reconciliation; it does not allow blind re-dispatch.

Official API references inspected 2026-10-05:

- [Contents API](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents): creation payload and immutable-ref content reads.
- [Repository commits API](https://docs.github.com/en/rest/commits/commits#get-a-commit): branch/ref resolution, parents and changed-file observations.
- [Repository API](https://docs.github.com/en/rest/repos/repos#get-a-repository): stable repository ID/node and current name.

## Evidence

`before_projection.py` calls the existing base Broker's real generic HTTP
projection. `before-projection.log` records two distinct effect IDs for the same
reviewed file creation when only a trace header digest changes. This is a
projection-reset counterexample, not evidence that an unauthorized live effect
occurred. `before-module.log` is the initial missing-module test failure.

`after.log/xml` preserves the first 66 passing pure-module tests. The expanded
`final.log/xml` contains 100 passing cases; no earlier failure was overwritten.
Tests exercise actual installed Protocol `8e5bc9e...` and Scan `ee971b43...`, with
no Protocol source overlays. They use synthetic GitHub bodies and no network,
accounts, tokens, or model calls. The full Airlock suite and real integrated
Permit/Kernel edge remain the root integration's responsibility.

Reproduce in this checkout with the exact installed candidate dependencies:

```bash
PYTHONPATH=src .venv/bin/python -m pytest --noconftest -q tests/test_github_consequence.py
.venv/bin/ruff check src/actenon_airlock/github_consequence.py tests/test_github_consequence.py
```

`--noconftest` isolates the pure module from the existing application-wide broker
fixtures. It does not skip a module test or replace the required integrated
regressions. No PR, push, merge, release, live resource action, or AIRLOCK-001 run
is performed in this subtask.
