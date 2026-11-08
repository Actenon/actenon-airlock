# Local dry run of reproduce.sh (technical rehearsal; NOT an operator result)

Run by the people who built Airlock, on their own machine. It shows the harness works end to
end. It does **not** count toward release-bar item 9, which needs two independent humans on
fresh machines.

- Candidate: `dc7ed54f93dd8d961029bb1dc50f499ed13e9dce`
- Fetched from the local repository (`REPO_URL` set), because C2 is not pushed yet. An operator
  fetches it from GitHub.
- Overall: **NOT all checks matched; see below**

```text
date_utc=2026-11-08T20:05:38Z
os=Darwin 27.2.0 arm64
python=Python 3.12.13
git=git version 2.54.0 (Apple Git-157)
docker=29.9.2 Docker Desktop aarch64
pack_expected_sha256=74b62d4820a7e62b7b382abff41e61fd3870d63a5ed9c4cdf65ef2ae6a89fc5e
```

| Step | Result | Evidence |
|---|---|---|
| identity | OK | `results/identity.json` |
| build-wheel | OK | `results/wheel.sha256` |
| installed-dependencies | OK | `results/installed.json` |
| doctor | OK | `results/doctor.json` |
| junit-integration | OK | `results/junit-integration.json` |
| junit-container | FAIL | `results/junit-container.json` |
| journals | OK | `results/journals.json` |
| tamper-self-test | OK | `tamper: 3 of 3 rejected` |
| provider | OK | `results/provider.json` |

| Detail | Observed |
|---|---|
| Identity | commit `dc7ed54f93dd…`, source digest `da323e93157e33ac…`, files 37 |
| Installed dependency commits | actenon-airlock `?`, actenon-kernel `ead6a00`, actenon-permit `85aa3ae`, actenon-protocol `a2e0e08`, actenon-scan `1638822` |
| Integration suite | 2377 passed, 62 skipped in 134.59s (0:02:14) |
| Container suites | 1 failed, 197 passed in 171.35s (0:02:51); 1 failed in 1.56s |
| Contract, integration | {'test-results.xml': {'cases': 2439, 'failed': 0, 'skipped': 62, 'unexpected_skips': [], 'required_not_passed': []}} |
| Contract, container | {'protected-results.xml': {'cases': 198, 'failed': 1, 'skipped': 0, 'unexpected_skips': [], 'required_not_passed': ['tests.test_codex_container::test_codex_executed_transport_attacks_have_working_controls']}, 'independent-boundary-results.xml': {'cases': 1, 'failed': 1, 'skipped': 0, 'unexpected_skips': [], 'required_not_passed': ['tests.test_independent_container::test_owned_transport_controls_and_protected_boundary']}} |
| Independent verifier | 142 journals, 1237 receipts; problems: [] |

Images built from the candidate's Dockerfiles (non-reproducible, recorded only):

```text
actenon-airlock-compute:dev sha256:c22d9c21ec88b8fe02e2f0af4a7534c0bea31e824713d40bb5c8c3304b3aaf4d
actenon-airlock-claude-code:v1 sha256:8ed0978b9fec7a875d325edda822fd7ba067fe2700ec413db082c2512ca02484
actenon-airlock-codex-cli:v1 sha256:79448b5fbcf0b1598b4dc34ad18dd3c76a4f4866c40f658f889b8507c1b1fce4
airlock-example-go:ci sha256:a9b70f1440f9649b7477ba61890f4f3bd10c6b3f6a0150e8a97cf91b94a19edc
airlock-example-node:ci sha256:06910ca2b772a5cd017879aafe0fd8821ead1b2b736e0c426746e94522901ed4
```

## The two container failures, and what the reruns showed

`report.json` is **not** all green. In this run, two container tests failed in the same way:

- `tests/test_codex_container.py::test_codex_executed_transport_attacks_have_working_controls`;
- `tests/test_independent_container.py::test_owned_transport_controls_and_protected_boundary`.

Both failed with `AirlockError: Protected Mode Docker operation failed: run`. Docker refused the
`docker run` that starts each test's control endpoint, on a just-created IPv6 network. Docker's
own message is suppressed by design.

- **Same images, immediately after:** the Codex test passed 2 of 2, and the independent test
  passed 5 of 5.
- **Earlier the same day, with the frozen images:** both passed in the C1 and the C2 container
  runs.
- **Load:** this run started under heavy local load. Its `git clone` printed
  `fork(): Resource temporarily unavailable`.

Classification: **INTERMITTENT ENVIRONMENT** (Docker Desktop under load). This is not a pass.
`OPERATOR_GUIDE.md` now pre-registers how an operator reports it. Every other check matched
`expected.json`:

- identity;
- the installed dependency commits;
- doctor;
- the integration contract (2,377 passed, 62 allowed skips);
- the independent verifier (142 journals, 1,237 receipts, 0 problems);
- the tamper self-test (3 of 3 rejected);
- the provider records.

`doctor` reports `commit: null` because Airlock was installed from a local wheel, not from Git.
The source identity is checked separately, in step 1.
