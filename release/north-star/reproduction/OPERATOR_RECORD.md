# Operator record: Airlock independent reproduction

Fill this in yourself during the run. Write what you observed, not what you expected.

- Operator (name or handle, as you wish to be recorded):
- Date and time started / finished (UTC):
- I did not build any Actenon component, and nobody from Actenon helped me during this run: yes / no
- If anyone helped: who, when and with what:

## Machine

- Fresh machine or freshly created VM? How was it prepared?
- Any Actenon software, state or images present before you started? (expected: none)
- OS and architecture (`uname -srm`):
- Python (`python3 --version`):
- Docker (`docker info --format '{{.ServerVersion}} {{.OperatingSystem}}'`):

## Identity

- Pack commit you checked out:
- SHA-256 of `expected.json` (`shasum -a 256 …`), and does it match what the owner gave you?
- Candidate commit, from `results/identity.json`:
- Source digest, from `results/identity.json`:
- Wheel SHA-256, from `results/wheel.sha256`:

## Commands run

List every command you ran, in order, including anything beyond `reproduce.sh`:

## Results

| Step | Expected | Observed | ENVIRONMENT / MISMATCH / NON-REPRODUCIBLE / OK |
|---|---|---|---|
| Identity | matches | | |
| Installed dependencies | 4 expected commits | | |
| Doctor | ok | | |
| Images built | IDs recorded | | |
| Integration suite | 0 failed, contract skips only | | |
| Container suites | 0 failed, 0 skipped, required tests pass | | |
| Independent verifier | 142 journals, 1,237 receipts, all OK | | |
| Tamper self-test | 3 of 3 rejected | | |
| Provider records | consistent | | |

## Deviations and failures

Describe anything that did not go as `OPERATOR_GUIDE.md` says, with exact messages:

## Support

What help, documentation or searching did you need, and at which step?
