#!/usr/bin/env python3
"""Independently verify a candidate's exact-head CI run from GitHub's own records.

Uses only the GitHub REST API (through `gh api`) and the standard library. It never runs
Airlock code. For the run of `.github/workflows/ci.yml` whose head is the candidate commit,
it checks:

  - every job concluded success, in one run, from this repository;
  - each artifact's downloaded bytes match the SHA-256 digest GitHub recorded;
  - the JUnit reports satisfy the candidate's own committed CI contract
    (reproduction/check_results.py junit, which follows the gate's rules);
  - every dependency CI installed, from pip's own installation reports where present (D9),
    is what the candidate's uv.lock pins: the locked commit, or a locked wheel from PyPI;
  - the registry rehearsal's reports, where present, meet the same contract as the jobs they
    mirror.

Usage: verify_ci.py CANDIDATE_SHA CANDIDATE_CHECKOUT OUT_DIR
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

REPO = "Actenon/actenon-airlock"
HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE / "reproduction" / "expected.json").read_text())
PYPI_FILES = "https://files.pythonhosted.org/"
REPORT_ARTIFACTS = (
    "integration-python-3.11",
    "integration-python-3.12",
    "protected-container-acceptance",
)
REHEARSAL_REPORTS = {
    "rehearsal-integration-results.xml": ("integration-python-3.12", "test-results.xml"),
    "rehearsal-protected-results.xml": ("protected-container-acceptance", "protected-results.xml"),
    "rehearsal-independent-results.xml": (
        "protected-container-acceptance",
        "independent-boundary-results.xml",
    ),
}
CONTRACT_ARTIFACTS = {
    "integration-python-3.11": ["test-results.xml"],
    "integration-python-3.12": ["test-results.xml"],
    "protected-container-acceptance": ["protected-results.xml", "independent-boundary-results.xml"],
}


def api(path: str, raw: bool = False):
    out = subprocess.check_output(
        ["gh", "api", path, *(["-H", "Accept: application/vnd.github+json"])]
    )
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

    lock = tomllib.loads(
        subprocess.check_output(["git", "-C", checkout, "show", f"{sha}:uv.lock"]).decode()
    )
    pins = {}
    for pkg in lock.get("package", []):
        name, source = pkg.get("name", ""), pkg.get("source") or {}
        if name.startswith("actenon-") and name != "actenon-airlock":
            if "git" in source:
                pins[name] = ("git", source["git"].rpartition("#")[2])
            elif "registry" in source:
                pins[name] = (
                    "registry",
                    {str(w.get("hash", "")).removeprefix("sha256:") for w in pkg.get("wheels", [])},
                )
    facts["lock_sources"] = {n: kind for n, (kind, _) in pins.items()}

    # pip's own installation reports, where CI produced them (D9): bind each to the lock.
    facts["install_reports"] = {}
    for name in REPORT_ARTIFACTS:
        path = out / name / "install-report.json"
        if not path.exists():
            continue
        report = json.loads(path.read_text())
        seen = {}
        for item in report.get("install", []):
            dep = (item.get("metadata") or {}).get("name", "")
            if not dep.startswith("actenon-") or dep == "actenon-airlock":
                continue
            info = item.get("download_info") or {}
            commit = (info.get("vcs_info") or {}).get("commit_id")
            digest = ((info.get("archive_info") or {}).get("hashes") or {}).get("sha256")
            seen[dep] = commit or digest
            kind, want = pins.get(dep, (None, None))
            if kind == "git" and commit != want:
                problems.append(f"{name}: installed {dep} at {commit}, but uv.lock pins {want}")
            elif kind == "registry" and (
                digest not in want or not str(info.get("url", "")).startswith(PYPI_FILES)
            ):
                problems.append(f"{name}: installed {dep} {digest}, not a locked wheel from PyPI")
            elif kind is None:
                problems.append(f"{name}: installed {dep}, which uv.lock does not pin")
        missing = sorted(set(pins) - set(seen))
        if missing:
            problems.append(f"{name}: install report omits {missing}")
        facts["install_reports"][name] = seen

    # Pre-registry candidates also record git installs in pip freeze; check them as before.
    installed = {}
    for name in ("integration-python-3.11", "integration-python-3.12"):
        text = (
            (out / name / "installed.txt").read_text()
            if (out / name / "installed.txt").exists()
            else ""
        )
        for line in text.splitlines():
            m = re.match(
                r"(actenon-[a-z]+) @ git\+https://github\.com/Actenon/[^@]+@([0-9a-f]{40})", line
            )
            if m:
                installed.setdefault(m[1], set()).add(m[2])
    facts["installed_dependency_commits"] = {k: sorted(v) for k, v in installed.items()}
    for dep, (kind, want) in pins.items():
        if kind == "git" and installed.get(dep) != {want}:
            problems.append(
                f"CI installed {dep} at {sorted(installed.get(dep, []))}, uv.lock pins {want}"
            )

    # The registry rehearsal (D9) is scored against the same contract as the jobs it mirrors.
    rehearsal = out / "registry-rehearsal"
    if rehearsal.exists():
        facts["registry_rehearsal"] = {}
        grouped: dict[str, list[str]] = {}
        for file, (artifact, contract_file) in REHEARSAL_REPORTS.items():
            found = list(rehearsal.rglob(file))
            if len(found) != 1:
                problems.append(f"registry-rehearsal: {file} not found exactly once")
                continue
            staged = out / "_rehearsal" / artifact / contract_file
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(found[0].read_bytes())
            grouped.setdefault(artifact, []).append(str(staged))
        for artifact, paths in grouped.items():
            result = subprocess.run([sys.executable, str(checker), "junit", checkout, artifact, *paths],
                                    capture_output=True, text=True)  # fmt: skip
            report = json.loads(result.stdout)
            facts["registry_rehearsal"][artifact] = report["reports"]
            problems += [f"registry-rehearsal (as {artifact}): {p}" for p in report["problems"]]
        rep = list(rehearsal.rglob("install-report.json"))
        facts["registry_rehearsal"]["install_report_entries"] = (
            sorted(i["metadata"]["name"] for i in json.loads(rep[0].read_text())["install"]
                   if i["metadata"]["name"].startswith("actenon-")) if len(rep) == 1 else None
        )  # fmt: skip

    result = {"schema": "actenon-airlock/independent-ci-verification/v1", "candidate": sha,
              "ok": not problems, "problems": problems, **facts}  # fmt: skip
    (out / "independent-ci-verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
