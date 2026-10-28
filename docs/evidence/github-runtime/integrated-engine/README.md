# Protected GitHub integration evidence

**23 tests passed using actual installed Scan, Permit, Protocol and Kernel.**
Only provider HTTP transport is replaced with `httpx.MockTransport`.
There was no live GitHub request, paid model call or container acceptance run.
These results do not establish real provider truth, useful-agent acceptance,
or independent reproduction.

The new test file is `work/actenon-airlock-github/tests/test_github_protected_integration.py`.
The coherent installed dependency identities and exact working source hashes
are recorded in `manifest.json`. The root runtime changes are still a working
candidate, so the manifest distinguishes its HEAD from working-tree hashes.

`before-preflight.log/xml` reproduces two receipt failures: wrong repository ID
or branch head caused authenticated GETs and zero PUTs, but the receipt claimed
no credential release. `before-integration.log/xml` preserves the intermediate
16-pass / 2-fail run. The root runtime repair makes credential release truthful
and labels the preflight separately from creation. `after-integration.log/xml`
is the complete 23-pass run.

The tests cover:

- Host-signed exact profile and finite Permit effect grant, actual Kernel claim
  before credential materialization, canonical request bytes, budget debit,
  and signed AMBIGUOUS receipt even after a 201 response.
- Wrong repository/head preflight: token-bearing reads are reported, no creation
  is attempted. This is distinct from post-dispatch ambiguity.
- Modified content, branch, path, message and unsupported body fields denied;
  issue creation, repository deletion and secret-egress targets never reach
  the transport.
- Trace/session changes, broker restart and a newly signed parent anchor do not
  clear ownership of an ambiguous consequence. A separately reviewed file still
  works. Removed source authority cannot survive through an older profile.
- The model grant cannot authorize the GitHub capability; a changed signed
  intent is rejected by the actual independent Kernel before any HTTP request.
- Changing the signed approval without its signature is rejected.

`fixture-receipts/` contains copied test receipt journals plus only their public
approval keys and signed approvals. No signing keys, grant-store files or real
credentials are included. `verify_fixture_receipts.py` verifies their signatures
and chain integrity without a provider connection. `offline-integrity.json`
records that check. The fixture public keys are not external trusted roots, and
without an externally anchored terminal head, tail truncation/completeness is
not proven. Provider truth remains **SYNTHETIC_FIXTURE_ONLY**.

Reproduce from the candidate checkout:

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q tests/test_github_protected_integration.py
.venv/bin/python ../../outputs/amended-north-star/github-protected-integration/verify_fixture_receipts.py
```

Root owns the full original regression run and integration commit. No additional
runtime file, PR, push, merge, release or live-resource action was performed by
this testing subtask.
