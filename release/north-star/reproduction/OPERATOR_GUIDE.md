# Independent reproduction: operator guide (release-bar item 9)

**Pre-registered on 2026-11-08. Not yet used by any operator.** This is the formal
reproduction for release-bar item 9 ("Two independent operators on fresh machines"). It is
**not** Adoption Trial V1, which is a separate, frozen onboarding study.

## What you are asked to do

Reproduce, on your own fresh machine and without help from the people who built it, the
evidence that Actenon Airlock's candidate is what it claims to be:

1. **Identity.** You fetch the exact candidate commit, and check its source digest yourself.
2. **Clean install.** You build its wheel and install it, not in editable mode, in a fresh
   environment. You check the exact dependency commits that were installed.
3. **Behaviour.** You build the images from the candidate's own Dockerfiles. You run the same
   integration and container test suites CI runs, including:
   - the real-boundary attacks;
   - credential isolation;
   - the independent containment test;
   - Claude Code and Codex CLI running through the boundary against a scripted model.

   Then you check every result against the candidate's own committed CI contract.
4. **Evidence.** You build an independent verifier, written in Go with no Airlock code, and use
   it to verify every published receipt journal. You check that it rejects tampered copies.
5. **Provider records.** You check that the published records of the one historical real GitHub
   write agree with each other.

## What this does not do

- **No model calls and no GitHub writes.** You do not rerun the paid live experiments.
- **Checking provider truth needs access.** For the historical GitHub write you can only check
  that the published records are consistent, because the repository is private. If the owner
  grants operators read access to the disposable repository of a future live run, you can then
  confirm GitHub's own state directly, and the guide's step 7 will name it.
- **It does not prove the agent's work is correct**, or that the boundary holds against a kernel
  or Docker escape (see the candidate's `docs/security-model.md`).

## Who may be an operator

See `RECRUITMENT.md`. In short:

- You are a person who did not build any Actenon component.
- You are not Claude, Codex or another agent.
- You use a fresh machine or a freshly created VM, with no Actenon installation or state.
- Nobody from Actenon helps you during the run.

## Supported environments

| Environment | Status |
|---|---|
| Linux x86_64 with Docker Engine, Python 3.11 or 3.12 | Supported |
| macOS on Apple silicon with Docker Desktop, Python 3.11 or 3.12 | Supported |
| Windows, WSL, rootless or remote Docker, Podman, Colima | **Unsupported** for this reproduction: record and stop |
| Machines without about 15 GB free disk, or without network access to GitHub, PyPI, Docker Hub, npm and Debian mirrors | Unsupported: record and stop |

## Run it

```bash
git clone https://github.com/Actenon/actenon-airlock.git airlock-pack
cd airlock-pack && git checkout <PACK_COMMIT>
bash release/north-star/reproduction/reproduce.sh
```

`<PACK_COMMIT>` is the commit the owner gives you. Check that
`release/north-star/reproduction/expected.json` has the SHA-256 the owner also gives you
(`shasum -a 256 release/north-star/reproduction/expected.json`). The script takes about 20–40
minutes, most of it building images and running the container suites.

## Expected outcome

Everything is in `expected.json`. In words:

| Step | Expected |
|---|---|
| Identity | The commit and source digest match `expected.json` |
| Installed dependencies | Scan, Protocol, Kernel and Permit at the four expected commits |
| Integration suite | 0 failed; every skip is allowed by the candidate's CI contract |
| Container suites | 0 failed, 0 skipped; every required test passed |
| Independent verifier | Its source hash matches; 142 journals and 1,237 receipts, all intact, each with the expected head and completeness |
| Tamper self-test | 3 of 3 tampered journals rejected |
| Provider records | The reviewed bytes, Airlock's readback and the separate-token readback agree |

`report.json` lists every check with `exit` 0 or 1.

## When something differs

Classify each difference, in `OPERATOR_RECORD.md`, as exactly one of:

- **ENVIRONMENT:** your machine could not run a step for reasons outside Airlock (Docker, disk,
  network, an unsupported OS). Record what happened, and stop or work around it. Say which.
- **MISMATCH:** a step ran and its result differs from `expected.json`. Record the file and
  values. Do not try to fix it.
- **NON-REPRODUCIBLE:** image IDs. These are expected to differ (the builds are not
  bit-reproducible), and they are recorded but not scored.

## Sending your evidence

Send `OPERATOR_RECORD.md` (filled in), `report.json` and the `results/` folder.

They contain:

- test outcomes and hashes;
- the verifier output;
- your OS, Python and Docker versions.

They contain no credentials, because none are used. Before sending, remove anything else you
do not want to share, such as your user name in paths. Do not send anything from `~/.docker`
or elsewhere outside `$WORK`.
