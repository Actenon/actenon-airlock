# Coordinated Scan change (to open on Actenon/actenon-scan)

Patch: `0001-Name-tiktoken-encoding-downloads-fix-query-only-URL-.patch`. It is based on Scan
`a9de0ffed2ed67aa1565ab5382898468ca998ff8`, the commit Airlock pins; the local commit is `c94d1d0e`.

Apply and open:

```sh
git clone https://github.com/Actenon/actenon-scan && cd actenon-scan
git checkout -b feat/runtime-vocabulary a9de0ffed2ed67aa1565ab5382898468ca998ff8
git am /path/to/actenon-airlock/docs/scan-pr/0001-*.patch
python -m pytest -q   # 1348 passed, 12 skipped, 4 xfailed
```

## Suggested PR title

Name tiktoken encoding downloads; fix query-only URL hosts; export normalise_path

## Suggested PR body

Runtime enforcement (Actenon Airlock) only allows effects that Scan names at a resolved callsite.
Running pr-agent and gpt-engineer under Airlock found two vocabulary gaps and one API gap:

1. `tiktoken.get_encoding("cl100k_base")` and `tiktoken.encoding_for_model("gpt-4o")` download
   `https://openaipublic.blob.core.windows.net/encodings/<encoding>.tiktoken` on first use. Scan now
   names that `http.get`. It is resolved for a literal encoding or a known model prefix and
   unresolved otherwise.
2. `classify_http("GET", "https://api.ipify.org?format=json")` named the resource
   `api.ipify.org?format=json`, while the same request with a `/` path was named `api.ipify.org`.
   The authority now ends at the first `/`, `?` or `#` (RFC 3986).
3. `normalise_path` is exported so runtime enforcement can spell filesystem resources exactly as the
   extractor does. Airlock currently imports `_normalise_path`.

Tests are in `tests/test_authority_evidence.py`; the full suite passes.

## Airlock side

Airlock already prefers `actenon_scan.authority.normalise_path` and falls back to the private name.
After the Scan PR merges, bump the `actenon-scan` pin in `pyproject.toml`. Acceptance with the
change installed is in `evidence/acceptance-20261004/coordinated-scan/`.

## Not in this change (next Scan work)

- GitHub GraphQL operation vocabulary. `github.graphql` is adapted today, but the grant covers any
  operation the credential permits.
- aiohttp request interception in Airlock. Scan already names aiohttp calls.
