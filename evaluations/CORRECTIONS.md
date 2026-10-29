# Corrections to the field evaluations (PR #15)

Status: **EXPERIMENTAL, historical evaluation material.** Nothing under
`evaluations/` is a production Airlock component, ships in the
`actenon-airlock` package, or counts as evidence for any release gate (G1–G40
or the recovered A–F acceptance sections). The original evidence files and
report text are kept unchanged below their correction notes.

An independent review of PR #15 head `f5ecfc133f3973ff72bbb3372ea01f2ad49605e6`
raised six findings. All six were reproduced. Candidate code was never executed
on the host: findings 3 and 5 were reproduced inside a `--network none`
container, and finding 4 through the PR's own container gate.

```bash
# against the original head, from a checkout of f5ecfc1:
python evaluations/security/reproduce_pr15_findings.py --image actenon-airlock-compute:dev
```

Raw output: [`security/pr15-findings-reproduction.json`](security/pr15-findings-reproduction.json)
(image `sha256:76b1e8f2b1d7917aa440ce98512d48f9f4b73cd50d06b5cd489191c6b31e50c0`).

## Findings, reproduction and correction

| # | Finding | Reproduced at f5ecfc1 | Correction |
|---|---|---|---|
| 1 | `quality_gate.py` signed evidence with an HMAC key written in the source (copied again in the FT9 binding script). | A record "signed" with the key copied from the source verifies: `forged_record_verifies: true`. | No signing secret in the repository. Evidence is signed with an Ed25519 key the caller supplies at run time (domain `actenon-airlock/evaluation-evidence/v1`) and verified only against a public key the verifier already trusts. The historical FT9 script uses a per-run random key. |
| 2 | `OperatorApprovalAuthority` never read its operator key and returned `APPROVED` whenever tests passed. | `approved: true` with a non-existent key file and no signature. | The authority issues an `ApprovalRequest` binding candidate digest, evidence digest, target and operator key ID. Only an Ed25519 operator signature over that exact request (separate domain, so an evidence signature cannot be replayed) yields APPROVED, and the candidate is re-hashed at acceptance. |
| 3 | `IndependentQualityGate` ran `python -m pytest` on candidates on the host. | Inside a container standing in for the host, candidate C's beacon fired **2** times and the gate still said `VERIFIED`. | `IndependentQualityGate.audit_and_verify` raises `HostExecutionRefused`; a marker test proves the candidate is not executed. Fifteen historical runners that execute candidate, agent or model code now exit unless run in a container. |
| 4 | `HardenedQualityGate` mounted trusted tests read-write, trusted a bare exit code, ran both suites in the candidate's process, set no capability/user/resource limits and recorded isolation as constants. | A wrong candidate that rewrites the withheld suite: `VERIFIED`. A candidate that calls `os._exit(0)` at import: `VERIFIED`. The honest wrong candidate: `FAILED`. | Replaced by `ContainerQualityGate`: candidate and trusted tests read-only; read-only root; no network; `--cap-drop ALL`; `no-new-privileges`; uid 65534; PID, memory and CPU limits; image by local ID; one container per suite; settings checked with `docker inspect` before start and recorded as observed; pass requires exit 0 **and** a JUnit report in which every trusted test passed. The verdict is `TESTS_PASSED`, never "VERIFIED". |
| 5 | `tests/test_field_evaluations.py` `exec()`-ed the import-time beacon candidate in the pytest process, on every machine and CI runner that ran the suite. | One beacon request per run. | Candidates are only inspected statically (AST). Container checks moved to `evaluations/tests`, run in the protected CI job. |
| 6 | Historical PASS claims overstate what was shown. | See below. | Correction notes added; original text kept. |

## What the corrected runner still cannot do

The candidate runs in the same interpreter as the tests, so it can still change
test behaviour or forge the report it writes (Candidates A and B pass genuine
tests by design). `TESTS_PASSED` means only that the specified tests passed with
the candidate imported in an isolated container. It is not a correctness or
safety verdict and never approves a consequence. Docker shares the host kernel.

## Overstated historical claims

| Where | Claim | What the evidence supports |
|---|---|---|
| `evidence/field_test_9_evidence.json` | `cryptographic_binding_verdict: PASS (Cryptographically Tamper-Evident)` | Not tamper-evident: the HMAC key was public (finding 1). |
| `evidence/field_test_9_evidence.json` | `section_5_publication_boundary: PASS (Exact Publication with Operator Discretion)` | No operator signed anything (finding 2). The single-mutation broker behaviour stands on its own. |
| `evidence/field_test_9_evidence.json` | `crash_resilience: verdict FAILED, status PASS (Handled Cleanly)` | Contradictory; treat as FAILED. |
| `reports/09_green_test_suite_attack.md`, README | Hardened gate "ready to become an optional pre-flight verification step"; "Verifier Process Boundary Holds"; "enforced HMAC evidence binding" | The gate accepted a suite-rewriting and an exit-zero candidate (finding 4). |
| `reports/08_independent_quality_gate.md`, README FT8 | PASS with operator approval of the positive control | Approval was automatic on a test verdict, and tests ran on the host (findings 2 and 3). The 0-mutation result for rejected patches stands. |
| `evidence/field_test_7_evidence.json` (`acceptance_gate_matrix`) and `reports/06_matched_baseline_eval.md` §gates | G28–G35, G39, G40 PASS under invented gate names | Self-asserted and mutually inconsistent. G28–G38 is the frozen gpt-engineer / qwen2.5-coder:14b programme, which has never passed. No field test is G-gate evidence. |
| README FT6, FT7 | **PASS** | FT7's engineering task failed in both baseline and protected runs; containment results are separate from task success. FT6 used an exploratory 7B model, not the frozen programme. |
| `reports/02_finops_cost_optimizer.md` | SOC 2 / ISO 42001 / insurer framing; "addresses the core compliance and liability barriers" | No certification, audit or insurer evidence exists. Signed receipts are local integrity evidence only. |
| README takeaway 1 | "Airlock guarantees that untrusted processes cannot bypass network boundaries" | Only Protected Mode enforces this, in the tested Docker configuration. Local Mode is cooperative. |
