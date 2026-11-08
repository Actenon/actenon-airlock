#!/usr/bin/env python3
"""Independently verify a candidate's exact-head CI run from GitHub's own records.

Uses only the GitHub REST API (through `gh api`) and the standard library. It never runs
Airlock code. For the run of `.github/workflows/ci.yml` whose head is the candidate commit,
it checks:

  - every job concluded success, in one run, from this repository;
  - each artifact's downloaded bytes match the SHA-256 digest GitHub recorded;
  - the JUnit reports satisfy the candidate's own committed CI contract
    (reproduction/check_results.py junit, which follows the gate's rules);
  - the dependency commits CI installed (installed.txt) equal the expected pins.

Usage: verify_ci.py CANDIDATE_SHA CANDIDATE_CHECKOUT OUT_DIR
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = "Actenon/actenon-airlock"
HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE / "reproduction" / "expected.json").read_text())
CONTRACT_ARTIFACTS = {
    "integration-python-3.11": ["test-results.xml"],
    "integration-python-3.12": ["test-results.xml"],
    "protected-container-acceptance": ["protected-results.xml", "independent-boundary-results.xml"],
}


def api(path: str, raw: bool = False):
    out = subprocess.check_output(["gh", "api", path, *(["-H", "Accept: application/vnd.github+json"])])
    return out if raw else json.loads(out)


def main(sha: str, checkout: str, out_dir: str) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    runs = [r for r in api(f"repos/{REPO}/actions/runs?head_sha={sha}&per_page=50")["workflow_runs"]
            if r["path"] == ".github/workflows/ci.yml"]  # fmt: skip
    if not runs:
        print(json.dumps({"ok": False, "problems": ["no CI run for this commit"]}))
        return 1
    run = sorted(runs, key=lambda r: r["run_number"])[-1]
    facts = {"run_id": run["id"], "event": run["event"], "head_sha": run["head_sha"],
             "head_branch": run["head_branch"], "status": run["status"], "conclusion": run["conclusion"],
             "repository": run["repository"]["full_name"], "head_repository": run["head_repository"]["full_name"],
             "html_url": run["html_url"]}  # fmt: skip
    if run["head_sha"] != sha or run["head_repository"]["full_name"] != REPO:
        problems.append("the run is not for this commit in this repository")
    if run["status"] != "completed" or run["conclusion"] != "success":
        problems.append(f"run is {run['status']}/{run['conclusion']}")
    jobs = api(f"repos/{REPO}/actions/runs/{run['id']}/jobs?per_page=50")["jobs"]
    facts["jobs"] = {j["name"]: j["conclusion"] for j in jobs}
    problems += [f"job {n!r} concluded {c!r}" for n, c in facts["jobs"].items() if c != "success"]

    artifacts = api(f"repos/{REPO}/actions/runs/{run['id']}/artifacts?per_page=100")["artifacts"]
    facts["artifacts"] = {}
    for art in artifacts:
        blob = api(f"repos/{REPO}/actions/artifacts/{art['id']}/zip", raw=True)
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        match = digest == art.get("digest")
        facts["artifacts"][art["name"]] = {"bytes": len(blob), "digest_matches_server": match}
        if not match:
            problems.append(f"artifact {art['name']}: downloaded bytes differ from GitHub's digest")
        target = out / art["name"]
        target.mkdir(exist_ok=True)
        zipfile.ZipFile(io.BytesIO(blob)).extractall(target)

    checker = HERE / "reproduction" / "check_results.py"
    facts["contract"] = {}
    for name, files in CONTRACT_ARTIFACTS.items():
        paths = [str(out / name / f) for f in files]
        result = subprocess.run([sys.executable, str(checker), "junit", checkout, name, *paths],
                                capture_output=True, text=True)  # fmt: skip
        report = json.loads(result.stdout)
        facts["contract"][name] = {"ok": report["ok"], "reports": report["reports"]}
        problems += report["problems"]

    installed = {}
    for name in ("integration-python-3.11", "integration-python-3.12"):
        text = (out / name / "installed.txt").read_text() if (out / name / "installed.txt").exists() else ""
        for line in text.splitlines():
            m = re.match(r"(actenon-[a-z]+) @ git\+https://github\.com/Actenon/[^@]+@([0-9a-f]{40})", line)
            if m:
                installed.setdefault(m[1], set()).add(m[2])
    facts["installed_dependency_commits"] = {k: sorted(v) for k, v in installed.items()}
    for dep, commit in EXPECTED["dependencies"].items():
        if installed.get(dep) != {commit}:
            problems.append(f"CI installed {dep} at {sorted(installed.get(dep, []))}, expected {commit}")
    result = {"schema": "actenon-airlock/independent-ci-verification/v1", "candidate": sha,
              "ok": not problems, "problems": problems, **facts}  # fmt: skip
    (out / "independent-ci-verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
