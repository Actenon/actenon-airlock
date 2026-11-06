# Contributing to Airlock

Airlock is maintained by one person. The most valuable contributions right now are reports
from people trying it for the first time.

## Try it and tell us what happened

Follow [getting started](docs/getting-started.md) on your own machine. Whether it works, breaks
or confuses you, [open an issue](https://github.com/Actenon/actenon-airlock/issues/new) with:

- what you ran, and where you got stuck or what surprised you;
- the output of `airlock doctor`;
- your OS and how you installed Python and Docker.

Getting stuck is a useful result. Please do not paste API keys, tokens, or files from
`.airlock/local/` (it holds your signing key, transcripts and patches). Read and redact any
log before you attach it.

## Report a security problem

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Report a bug in a check or a receipt

Airlock's receipts must never claim more than was observed. If a receipt, the demo or
`airlock doctor` says something happened that did not, or says PASS when tests did not run,
that is a serious bug: please report it with the exact output.

## Change the code

~~~sh
git clone https://github.com/Actenon/actenon-airlock.git && cd actenon-airlock
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[test]"
python -m pytest -q
ruff check src tests && ruff format --check src tests
~~~

The real-container tests need Docker and the images; CI shows how they are built
(`.github/workflows/ci.yml`, job `protected`). Keep changes small and focused, add a test that
fails without your change, and do not weaken a check to make a test pass.

## Compatibility and adapters

Useful, bounded contributions:

- a project layout whose checks Airlock picks wrongly (Python, Go, TypeScript);
- a toolchain recipe in `examples/toolchains` for another language, with a test;
- a new agent version that behaves differently through the boundary.

New external integrations (other APIs, MCP tools, payments) need their own reviewed
consequence and readback model before they can be supported. Please open an issue to discuss
one before writing code.

## Documentation

The install command appears in several files and must be the same exact commit everywhere.
`python scripts/check_readme_install.py` checks that; CI runs it, and runs the documented
install from scratch.
