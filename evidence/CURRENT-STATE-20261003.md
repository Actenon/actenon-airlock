# Airlock implementation state — 3 October 2026

PROVEN:

- Created a new public repository under Actenon, not the personal account.
- Started implementation on feat/unified-airlock.
- Scan PR #100 is merged at a9de0ffed2ed67aa1565ab5382898468ca998ff8; used its existing structured extractor.
- All five release-candidate heads match the supplied hashes in github-baseline.json.
- No parent repository was changed, merged, tagged, or published.
- The preserved release graph, final gates, and owner actions were inspected in the kernel checkout.
- Four runtime dependencies are pinned to full Git commit identities.
- The CLI supplies init, run, diff, check, and doctor.
- Runtime decisions use real Permit scopes and real Kernel Ed25519 verification, revocation, and replay protection.

LIMITS:

- Cooperative Python HTTP clients are supported; this is not an OS sandbox for hostile/native code.
- Unresolved/template authority and unsupported effects remain blocked.
- GitHub repository-scoped actions use Scan's vocabulary; generic HTTP uses exact URLs.
- Provider SDK integration uses real SDKs with offline resource responses. No live API write was performed.
- Full operation on three independent external agent repositories has not been demonstrated.
- Existing ecosystem publication/owner-action gates remain pending; candidate dependencies are installed from Git.

VALIDATION EVIDENCE:

- initial-local-tests.xml preserves the first 39 pass / 2 fail run.
- provider-first-tests.xml preserves the expanded 44 pass / 3 fail run.
- The corrected test results are in local-tests.xml.
- Local wheel/sdist build output is in local-build.log.
- GitHub Actions uploads JUnit, installed dependency identities, doctor output, and development builds.
- GitHub checks and merge evidence are recorded after the PR completes.

PUBLICATION:

No package, tag, release, advisory, or ecosystem release step is authorized by this implementation.
The release graph requires pending owner actions and staged release verification. Airlock adds no publish workflow.
