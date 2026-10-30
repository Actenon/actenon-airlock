# Repository settings for enforced releases (owner applies)

These are prepared, not applied: changing repository settings needs owner
authority. Together with `.github/workflows/release.yml` they make publication
depend on admission rather than merely reporting it.

| Setting | Effect |
|---|---|
| `branch-protection-main.json` | `main` requires the four CI checks (from GitHub Actions, app 15368), one review, resolved conversations; no force-push or deletion |
| `tag-ruleset.json` | Only GitHub Actions can create, move or delete `v*` tags, so a release tag cannot appear without the release workflow |
| `environment-pypi-release*.json` | The `publish` job waits for a named reviewer and can only deploy from `main` |

```sh
gh api -X PUT repos/Actenon/actenon-airlock/branches/main/protection --input release/settings/branch-protection-main.json
gh api -X POST repos/Actenon/actenon-airlock/rulesets --input release/settings/tag-ruleset.json
# replace <OWNER_USER_ID> first: gh api users/<login> --jq .id
gh api -X PUT repos/Actenon/actenon-airlock/environments/pypi-release --input release/settings/environment-pypi-release.json
gh api -X POST repos/Actenon/actenon-airlock/environments/pypi-release/deployment-branch-policies --input release/settings/environment-pypi-release-branches.json
```

Then register `release.yml` as a PyPI trusted publisher for `actenon-airlock`
(environment `pypi-release`). No PyPI token is stored anywhere.

Remaining limits: a repository admin can still edit workflows or settings, and
the tag ruleset trusts every GitHub Actions workflow in this repository, not
only `release.yml`; keep workflow changes behind review on `main`.
