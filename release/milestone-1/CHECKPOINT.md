# Milestone 1 checkpoint (branch feat/airlock-milestone-1, base 426bdaa)

Resume: `git checkout feat/airlock-milestone-1` in actenon-airlock; venv with
`uv venv -p 3.12 .venv && uv pip install -e ".[test]"`; `pytest -q` (497 passed, 2 Docker skips).

## Done (commits on this branch)
1. `2a9a249` release.yml: admission before build/publish/tag; tag trigger removed;
   owner settings in release/settings (not applied). 14 tests.
2. `4eaf679` offline evidence: `airlock checkpoint`, `airlock verify-evidence`;
   integrity / completeness / provider truth. 15 tests.
3. next commit: effect identity ignores non-semantic headers; broker refuses to
   start when the store lost journal-recorded effects. 18 tests.

## Remaining, in order
- C3 probes in tests/test_protected.py contained script: IPv6, DNS, proxy env,
  ctypes/native socket, Docker socket absence, /proc and env credential probes.
- Guided workflow: product synthetic GitHub provider (move ProviderFixture out of
  tests), `airlock demo`-style end-to-end with verification + operator approval.
- Real third-party agent screening (local Ollama, Metal) and v2 programme spec;
  prepare (not run) the A100 notebook.
- B1–B3 cross-language corpus (Kernel SDK runners: go/cargo/node present locally).
- A2 SDK pins, ops docs (docs/operations.md referenced by the store-loss error),
  OWASP matrix, install guide, push + draft PR + CI, gate report.
