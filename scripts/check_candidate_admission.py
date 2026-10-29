#!/usr/bin/env python3
"""Release-admission gate for Actenon Airlock (G1-G40).

Every PASS is derived from evidence this script fetches itself from an
authenticated source and binds to the exact candidate commit:

* CI evidence comes from the GitHub Actions API (check runs, workflow runs,
  jobs and artifacts) for ``--candidate-sha``. Artifacts are downloaded from
  the run that produced them and their bytes must match the server-recorded
  SHA-256 digest. Local files such as ``summary.json`` are never consulted,
  so a report written by hand cannot satisfy any gate.
* The frozen G28-G38 external coding-agent programme additionally requires a
  Sigstore build-provenance attestation, verified with ``gh attestation
  verify``, proving the evidence files were produced by
  ``real-coding-acceptance.yml`` from the candidate commit on a GitHub-hosted
  runner. The evidence must match the frozen model, model digest, external
  agent revision and scoring configuration in ``release/gates.json`` and the
  candidate's own dependency manifest.
* Candidate files (``pyproject.toml``, ``uv.lock``, the frozen definitions)
  are read from the candidate commit object with ``git show``, not from the
  working tree.
* Registry coherence (release only) queries PyPI and compares published file
  digests with ``uv.lock``.

Missing, malformed, stale, skipped, inconsistent or unauthenticated evidence
never yields PASS. Gates whose frozen definition is not committed are
UNDEFINED, which also blocks readiness.

Trust assumptions and limits: GitHub (API, Actions OIDC, artifact storage)
and the Sigstore public-good instance are the trusted issuers. An attestation
proves which workflow and commit produced a file, not that the file's claims
are true: a candidate that rewrites its own acceptance harness could emit a
false summary from a genuine run. The frozen configuration hashes of the
harness (driver, scoring tests, dependencies, preprompts) limit that, and
reviewers must still review harness changes. Image identity is recorded but
not independently rebuilt.

Exit status: 0 when the overall status meets ``--require``, 1 when it does
not, 2 when the registry or candidate cannot be evaluated at all.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

STATUSES = ("NOT READY", "CANDIDATE READY", "RELEASE READY")
PASS, FAIL, BLOCKED, UNDEFINED = "PASS", "FAIL", "BLOCKED", "UNDEFINED"
GATE_IDS = tuple(f"G{n}" for n in range(1, 41))
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
FAILED_CONCLUSIONS = {"failure", "cancelled", "timed_out", "action_required", "startup_failure"}


class AdmissionError(Exception):
    """The registry or candidate cannot be evaluated; nothing may be admitted."""


class EvidenceError(Exception):
    """A specific piece of evidence is missing, malformed or untrusted."""


@dataclass
class Result:
    status: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "detail": self.detail, "evidence": self.evidence}


class GitHub(Protocol):
    def check_runs(self, repo: str, sha: str) -> list[dict[str, Any]]: ...
    def workflow_runs(self, repo: str, sha: str) -> list[dict[str, Any]]: ...
    def jobs(self, repo: str, run_id: int) -> list[dict[str, Any]]: ...
    def artifacts(self, repo: str, run_id: int) -> list[dict[str, Any]]: ...
    def download_artifact(self, repo: str, artifact_id: int) -> bytes: ...
    def verify_attestation(
        self, repo: str, path: Path, signer_workflow: str, sha: str
    ) -> tuple[bool, str]: ...


class Registry(Protocol):
    def files(self, name: str, version: str) -> list[dict[str, Any]] | None: ...


class Tree(Protocol):
    def read(self, path: str) -> bytes | None: ...


# --------------------------------------------------------------------------
# Trusted sources
# --------------------------------------------------------------------------


class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Artifact downloads redirect to signed blob URLs; never forward the token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
        return new


class GitHubAPI:
    def __init__(self, token: str, api: str = "https://api.github.com") -> None:
        self._token = token
        self._api = api.rstrip("/")
        self._opener = urllib.request.build_opener(_NoAuthOnRedirect)

    def _request(self, url: str) -> bytes:
        req = urllib.request.Request(url)
        req.add_unredirected_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with self._opener.open(req, timeout=60) as resp:
                body = resp.read(MAX_ARTIFACT_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise EvidenceError(f"GitHub API {exc.code} for {url}") from exc
        except OSError as exc:
            raise EvidenceError(f"GitHub API unreachable for {url}: {exc}") from exc
        if len(body) > MAX_ARTIFACT_BYTES:
            raise EvidenceError(f"response from {url} exceeds {MAX_ARTIFACT_BYTES} bytes")
        return body

    def _json(self, path: str, **params: Any) -> dict[str, Any]:
        query = urllib.parse.urlencode(params)
        data = json.loads(self._request(f"{self._api}{path}{'?' + query if query else ''}"))
        if not isinstance(data, dict):
            raise EvidenceError(f"unexpected GitHub API payload for {path}")
        return data

    def _paged(self, path: str, key: str, **params: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for page in range(1, 11):
            data = self._json(path, per_page=100, page=page, **params)
            batch = data.get(key) or []
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise EvidenceError(f"too many results for {path}")

    def check_runs(self, repo: str, sha: str) -> list[dict[str, Any]]:
        return self._paged(f"/repos/{repo}/commits/{sha}/check-runs", "check_runs")

    def workflow_runs(self, repo: str, sha: str) -> list[dict[str, Any]]:
        return self._paged(f"/repos/{repo}/actions/runs", "workflow_runs", head_sha=sha)

    def jobs(self, repo: str, run_id: int) -> list[dict[str, Any]]:
        return self._paged(f"/repos/{repo}/actions/runs/{run_id}/jobs", "jobs", filter="latest")

    def artifacts(self, repo: str, run_id: int) -> list[dict[str, Any]]:
        return self._paged(f"/repos/{repo}/actions/runs/{run_id}/artifacts", "artifacts")

    def download_artifact(self, repo: str, artifact_id: int) -> bytes:
        return self._request(f"{self._api}/repos/{repo}/actions/artifacts/{artifact_id}/zip")

    def verify_attestation(
        self, repo: str, path: Path, signer_workflow: str, sha: str
    ) -> tuple[bool, str]:
        gh = shutil.which("gh")
        if gh is None:
            return False, "gh CLI unavailable; attestation cannot be verified"
        cmd = [
            gh, "attestation", "verify", str(path),
            "--repo", repo,
            "--signer-workflow", f"{repo}/{signer_workflow}",
            "--source-digest", sha,
            "--deny-self-hosted-runners",
            "--format", "json",
        ]  # fmt: skip
        env = {**os.environ, "GH_TOKEN": self._token}
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[:500]
        return True, f"Sigstore attestation verified for {path.name}"


class PyPI:
    def files(self, name: str, version: str) -> list[dict[str, Any]] | None:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                return json.load(resp).get("urls") or []
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise EvidenceError(f"PyPI {exc.code} for {name}=={version}") from exc
        except OSError as exc:
            raise EvidenceError(f"PyPI unreachable for {name}=={version}: {exc}") from exc


class WorkingTree:
    """The gate's own reviewed checkout: the source of the rules, not of evidence."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def read(self, path: str) -> bytes | None:
        target = self._root / path
        return target.read_bytes() if target.is_file() else None


class GitTree:
    """Reads files from the candidate commit object, never the working tree."""

    def __init__(self, repo_root: Path, sha: str) -> None:
        self._root = repo_root
        self._sha = sha
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo_root, capture_output=True
        )
        if probe.returncode != 0:
            raise AdmissionError(f"candidate commit {sha} is not present in {repo_root}")

    def read(self, path: str) -> bytes | None:
        proc = subprocess.run(
            ["git", "show", f"{self._sha}:{path}"], cwd=self._root, capture_output=True
        )
        return proc.stdout if proc.returncode == 0 else None


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


def load_registry(raw: bytes | None) -> dict[str, Any]:
    if raw is None:
        raise AdmissionError("release/gates.json is absent from the gate checkout")
    try:
        registry = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdmissionError(f"release/gates.json is malformed: {exc}") from exc
    if registry.get("schema") != "actenon-airlock/release-gates/v1":
        raise AdmissionError("release/gates.json has an unknown schema")
    gates = registry.get("gates")
    if not isinstance(gates, list) or [g.get("id") for g in gates] != list(GATE_IDS):
        raise AdmissionError("release/gates.json must list G1..G40 exactly once, in order")
    for gate in gates:
        if gate.get("definition") not in {"MISSING", "PROGRAMME_LEVEL", "FROZEN"}:
            raise AdmissionError(f"{gate['id']}: unknown definition state")
        if gate["definition"] != "MISSING" and not gate.get("acceptance_condition"):
            raise AdmissionError(f"{gate['id']}: defined gate lacks an acceptance condition")
        if gate.get("evidence") not in {None, "frozen_external_acceptance"}:
            raise AdmissionError(
                f"{gate['id']}: unknown evidence producer {gate.get('evidence')!r}"
            )
        if not set(gate.get("required_for") or []) >= {"candidate", "release"}:
            raise AdmissionError(f"{gate['id']}: every G1-G40 gate is mandatory for both levels")
    prereq = registry.get("ci_prerequisites") or {}
    for spec in prereq.get("junit", []):
        for node in spec.get("allowed_skips", []):
            if not any(node in other.get("must_pass", []) for other in prereq["junit"]):
                raise AdmissionError(
                    f"skip of {node} is allowed but no mandatory report requires it to pass"
                )
    if not registry.get("frozen_external_acceptance", {}).get("frozen_configuration"):
        raise AdmissionError("frozen external acceptance configuration is missing")
    return registry


def check_frozen_definitions(registry: dict[str, Any], tree: Tree) -> Result:
    spec = registry["frozen_definitions"]
    pinned = spec.get("sha256")
    text = tree.read(spec["path"])
    if text is None or not pinned:
        return Result(
            BLOCKED,
            "frozen G1-G40 definitions are not committed and hash-pinned: " + spec.get("note", ""),
        )
    actual = hashlib.sha256(text).hexdigest()
    if actual != pinned:
        return Result(FAIL, f"{spec['path']} sha256 {actual} differs from pinned {pinned}")
    return Result(PASS, f"{spec['path']} matches pinned sha256 {pinned}")


# --------------------------------------------------------------------------
# GitHub Actions evidence
# --------------------------------------------------------------------------


def _latest_by_name(check_runs: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    matching = [
        c for c in check_runs
        if c.get("name") == name and (c.get("app") or {}).get("slug") == "github-actions"
    ]  # fmt: skip
    return max(matching, key=lambda c: c.get("id", 0)) if matching else None


def _trusted_run(run: dict[str, Any], repo: str, sha: str, workflow: str) -> bool:
    return (
        run.get("head_sha") == sha
        and run.get("path") == workflow
        and (run.get("repository") or {}).get("full_name") == repo
        and (run.get("head_repository") or {}).get("full_name") == repo
    )


def _artifact_bytes(gh: GitHub, repo: str, run: dict[str, Any], name: str, sha: str) -> bytes:
    found = [a for a in gh.artifacts(repo, run["id"]) if a.get("name") == name]
    if len(found) != 1:
        raise EvidenceError(f"run {run['id']} has {len(found)} artifacts named {name!r}")
    artifact = found[0]
    if artifact.get("expired"):
        raise EvidenceError(f"artifact {name!r} from run {run['id']} has expired")
    origin = artifact.get("workflow_run") or {}
    if origin.get("id") != run["id"] or origin.get("head_sha") != sha:
        raise EvidenceError(f"artifact {name!r} is not bound to run {run['id']} at {sha}")
    digest = artifact.get("digest") or ""
    if not digest.startswith("sha256:"):
        raise EvidenceError(f"artifact {name!r} has no server-recorded sha256 digest")
    blob = gh.download_artifact(repo, artifact["id"])
    if hashlib.sha256(blob).hexdigest() != digest.removeprefix("sha256:"):
        raise EvidenceError(f"artifact {name!r} bytes do not match digest {digest}")
    return blob


def _zip_member(blob: bytes, member: str) -> bytes:
    """Read the one archive entry whose path is ``member`` or ends in ``/member``.

    upload-artifact roots an archive at the common ancestor of its paths, so the
    same evidence file can carry a workspace prefix. Ambiguity fails closed.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            names = [
                n for n in archive.namelist()
                if (n == member or n.endswith("/" + member)) and ".." not in n.split("/")
            ]  # fmt: skip
            if len(names) != 1:
                raise EvidenceError(f"artifact has {len(names)} entries for {member}")
            return archive.read(names[0])
    except zipfile.BadZipFile as exc:
        raise EvidenceError(f"artifact is not a valid zip: {exc}") from exc


def junit_outcomes(xml_bytes: bytes) -> dict[str, str]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise EvidenceError(f"malformed JUnit XML: {exc}") from exc
    outcomes: dict[str, str] = {}
    for case in root.iter("testcase"):
        node = f"{case.get('classname')}::{case.get('name')}"
        if case.find("failure") is not None or case.find("error") is not None:
            outcome = "failed"
        elif case.find("skipped") is not None:
            outcome = "skipped"
        else:
            outcome = "passed"
        if node in outcomes:
            raise EvidenceError(f"duplicate JUnit test case {node}")
        outcomes[node] = outcome
    if not outcomes:
        raise EvidenceError("JUnit report contains no test cases")
    return outcomes


def check_ci_prerequisites(registry: dict[str, Any], gh: GitHub, repo: str, sha: str) -> Result:
    spec = registry["ci_prerequisites"]
    workflow = spec["candidate_workflow"]
    evidence: list[str] = []
    try:
        checks = gh.check_runs(repo, sha)
        runs = {r.get("check_suite_id"): r for r in gh.workflow_runs(repo, sha)}
        ci_run: dict[str, Any] | None = None
        for job in spec["candidate_jobs"]:
            check = _latest_by_name(checks, job)
            if check is None:
                return Result(BLOCKED, f"no GitHub Actions result for {job!r} on {sha}")
            run = runs.get((check.get("check_suite") or {}).get("id"))
            if run is None or not _trusted_run(run, repo, sha, workflow):
                return Result(FAIL, f"{job!r} did not come from {workflow} in {repo} at {sha}")
            if check.get("status") != "completed":
                return Result(BLOCKED, f"{job!r} has not completed")
            if check.get("conclusion") != "success":
                return Result(FAIL, f"{job!r} concluded {check.get('conclusion')!r}")
            if ci_run is not None and ci_run["id"] != run["id"]:
                return Result(FAIL, "required jobs come from different workflow runs")
            ci_run = run
            evidence.append(check.get("html_url") or f"check-run {check.get('id')}")
        assert ci_run is not None
        reports: dict[str, dict[str, str]] = {}
        for report in spec["junit"]:
            blob = _artifact_bytes(gh, repo, ci_run, report["artifact"], sha)
            outcomes = junit_outcomes(_zip_member(blob, report["file"]))
            reports[report["artifact"]] = outcomes
            failed = sorted(n for n, o in outcomes.items() if o == "failed")
            if failed:
                return Result(FAIL, f"{report['artifact']}: failing tests {failed[:5]}")
            skipped = {n for n, o in outcomes.items() if o == "skipped"}
            unexpected = sorted(skipped - set(report["allowed_skips"]))
            if unexpected:
                return Result(FAIL, f"{report['artifact']}: skipped tests {unexpected[:5]}")
            for node in report["must_pass"]:
                if outcomes.get(node) != "passed":
                    return Result(FAIL, f"{report['artifact']}: {node} did not pass")
            evidence.append(f"{report['artifact']}: {len(outcomes)} cases, skips {sorted(skipped)}")
    except EvidenceError as exc:
        return Result(BLOCKED, str(exc), evidence)
    return Result(PASS, f"all required CI jobs passed in run {ci_run['id']}", evidence)


def git_dependencies(lock: bytes | None) -> list[tuple[str, str, str]]:
    if lock is None:
        raise EvidenceError("uv.lock is absent from the candidate commit")
    try:
        data = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"uv.lock is malformed: {exc}") from exc
    deps = []
    for pkg in data.get("package", []):
        git = (pkg.get("source") or {}).get("git")
        if not git:
            continue
        url, _, rev = git.partition("#")
        match = re.match(r"https://github\.com/([^/]+/[^/?#]+?)(?:\.git)?(?:\?|$)", url)
        if match is None or not SHA_RE.match(rev):
            raise EvidenceError(
                f"{pkg.get('name')}: git source {git!r} is not a pinned GitHub commit"
            )
        deps.append((pkg["name"], match.group(1), rev))
    return deps


def check_dependency_graph(
    registry: dict[str, Any], gh: GitHub, tree: Tree, expected: dict[str, str]
) -> Result:
    required = registry["ci_prerequisites"]["dependency_jobs"]
    evidence: list[str] = []
    try:
        deps = git_dependencies(tree.read("uv.lock"))
        pinned = {repo: rev for _, repo, rev in deps}
        for repo, rev in sorted(expected.items()):
            if pinned.get(repo) != rev:
                return Result(
                    FAIL,
                    f"{repo} is locked at {pinned.get(repo)} but the candidate graph expects {rev}",
                )
        for name, repo, rev in deps:
            jobs = required.get(repo)
            if jobs is None:
                return Result(FAIL, f"{name} comes from {repo}, which has no reviewed CI contract")
            checks = gh.check_runs(repo, rev)
            bad = [
                c["name"] for c in checks
                if (c.get("app") or {}).get("slug") == "github-actions"
                and c.get("conclusion") in FAILED_CONCLUSIONS
            ]  # fmt: skip
            for job in jobs:
                check = _latest_by_name(checks, job)
                if check is None or check.get("conclusion") != "success":
                    state = "missing" if check is None else check.get("conclusion")
                    return Result(
                        BLOCKED if check is None else FAIL,
                        f"{repo}@{rev[:12]}: {job!r} is {state}",
                        evidence,
                    )
            if bad:
                return Result(
                    FAIL, f"{repo}@{rev[:12]}: failing checks {sorted(set(bad))}", evidence
                )
            evidence.append(f"{repo}@{rev}: {len(jobs)} required jobs passed")
    except EvidenceError as exc:
        return Result(BLOCKED, str(exc), evidence)
    return Result(PASS, f"{len(deps)} locked candidate dependencies have passing CI", evidence)


def check_frozen_acceptance(registry: dict[str, Any], gh: GitHub, tree: Tree, sha: str) -> Result:
    spec = registry["frozen_external_acceptance"]
    repo, workflow = spec["repository"], spec["workflow"]
    frozen = spec["frozen_configuration"]
    try:
        candidates = [r for r in gh.workflow_runs(repo, sha) if r.get("path") == workflow]
        runs = [
            r for r in candidates
            if _trusted_run(r, repo, sha, workflow) and r.get("event") in spec["events"]
        ]  # fmt: skip
        if not runs:
            ignored = [f"{r.get('id')} ({r.get('event')})" for r in candidates]
            detail = f"no trusted {workflow} run exists for candidate {sha}"
            return Result(
                BLOCKED, detail + (f"; ignored untrusted runs {ignored}" if ignored else "")
            )
        run = max(runs, key=lambda r: r["id"])
        url = run.get("html_url") or f"run {run['id']}"
        if run.get("conclusion") != "success":
            return Result(FAIL, f"latest {workflow} run concluded {run.get('conclusion')!r}", [url])
        job = next((j for j in gh.jobs(repo, run["id"]) if j.get("name") == spec["job"]), None)
        if job is None or job.get("conclusion") != "success":
            return Result(FAIL, f"job {spec['job']!r} did not succeed", [url])
        steps = {s.get("name"): s.get("conclusion") for s in job.get("steps") or []}
        for step in spec["required_steps"]:
            if steps.get(step) != "success":
                return Result(FAIL, f"step {step!r} concluded {steps.get(step)!r}", [url])
        blob = _artifact_bytes(gh, repo, run, spec["artifact"], sha)

        def member(path: str) -> dict[str, Any]:
            try:
                value = json.loads(_zip_member(blob, path))
            except json.JSONDecodeError as exc:
                raise EvidenceError(f"{path} is malformed: {exc}") from exc
            if not isinstance(value, dict):
                raise EvidenceError(f"{path} is not a JSON object")
            return value

        with tempfile.TemporaryDirectory() as tmp:
            for path in spec["attested_files"]:
                local = Path(tmp) / hashlib.sha256(path.encode()).hexdigest()
                local.write_bytes(_zip_member(blob, path))
                ok, detail = gh.verify_attestation(repo, local, workflow, sha)
                if not ok:
                    return Result(FAIL, f"{path}: provenance not verified: {detail}", [url])

        baseline_reg = member("baseline-agent-evidence/preregistration.json")
        protected_reg = member("real-agent-evidence/preregistration.json")
        baseline = member("baseline-agent-evidence/baseline-result.json")
        summary = member("real-agent-evidence/run-summary.json")
        acceptance = member("real-agent-evidence/acceptance.json")
        receipts = member("real-agent-evidence/receipt-verification.json")

        pyproject = tree.read("pyproject.toml")
        if pyproject is None:
            raise EvidenceError("pyproject.toml is absent from the candidate commit")
        manifest = hashlib.sha256(pyproject).hexdigest()
        for label, reg in (("baseline", baseline_reg), ("protected", protected_reg)):
            config = reg.get("configuration") or {}
            for key, value in frozen.items():
                if config.get(key) != value:
                    return Result(
                        FAIL, f"{label} configuration {key} differs from frozen value", [url]
                    )
            if config.get("airlock_dependency_manifest_sha256") != manifest:
                return Result(FAIL, f"{label} ran against a different dependency manifest", [url])
            canonical = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(canonical).hexdigest() != reg.get("configuration_sha256"):
                return Result(FAIL, f"{label} preregistration hash is inconsistent", [url])
        if baseline_reg["configuration"] != protected_reg["configuration"]:
            return Result(FAIL, "baseline and protected runs used different configurations", [url])
        if baseline.get("configuration_sha256") != baseline_reg["configuration_sha256"]:
            return Result(FAIL, "baseline result is not bound to its preregistration", [url])
        if baseline.get("status") != "PASS" or baseline.get("exit_status") != 0:
            return Result(FAIL, "matched unprotected baseline did not pass", [url])
        checks = {
            "model is not a fixture": summary.get("model_fixture") is False,
            "model": summary.get("model") == frozen["model"],
            "model digest": summary.get("model_digest") == frozen["model_digest"],
            "external agent revision": summary.get("source_head") == frozen["source_head"],
            "matched baseline": summary.get("matched_baseline_configuration_sha256")
            == baseline_reg["configuration_sha256"],
            "no run error": summary.get("error") in (None, ""),
            "unauthorised requests denied the run": summary.get("launch_result") == 3,
            "original source unchanged": summary.get("original_source_unchanged") is True,
            "protected host file unchanged": summary.get("protected_host_file_unchanged") is True,
            "engineering task passed": acceptance.get("after_tests") == "passed"
            and bool(acceptance.get("local_commit")),
            "receipts verify": receipts.get("ok") is True,
        }
        failed = [name for name, ok in checks.items() if not ok]
        if failed:
            return Result(FAIL, f"frozen acceptance evidence failed: {failed}", [url])
    except EvidenceError as exc:
        return Result(BLOCKED, str(exc))
    return Result(PASS, f"frozen programme passed in attested run {run['id']}", [url])


def check_registry_coherence(tree: Tree, pypi: Registry) -> Result:
    try:
        raw = tree.read("pyproject.toml")
        if raw is None:
            raise EvidenceError("pyproject.toml is absent from the candidate commit")
        project = tomllib.loads(raw.decode("utf-8"))["project"]
        version = project["version"]
        if re.search(r"(\.dev\d*|a\d+|b\d+|rc\d+|\+.*)$", version):
            return Result(FAIL, f"version {version} is a pre-release; candidates are not releases")
        direct = [d for d in project.get("dependencies", []) if "@" in d]
        if direct:
            return Result(FAIL, f"direct URL dependencies remain: {direct}")
        if git_dependencies(tree.read("uv.lock")):
            return Result(FAIL, "uv.lock still resolves git candidate sources")
        lock = tomllib.loads((tree.read("uv.lock") or b"").decode("utf-8"))
        evidence = []
        for pkg in lock.get("package", []):
            if not str(pkg.get("name", "")).startswith("actenon-") or "registry" not in (
                pkg.get("source") or {}
            ):
                continue
            files = pypi.files(pkg["name"], pkg["version"])
            if files is None:
                return Result(FAIL, f"{pkg['name']}=={pkg['version']} is not published on PyPI")
            published = {f.get("digests", {}).get("sha256") for f in files}
            locked = {
                str(w.get("hash", "")).removeprefix("sha256:")
                for w in pkg.get("wheels", []) + ([pkg["sdist"]] if "sdist" in pkg else [])
            }
            if not locked or not locked <= published:
                return Result(
                    FAIL, f"{pkg['name']}=={pkg['version']} locked hashes are not on PyPI"
                )
            evidence.append(f"{pkg['name']}=={pkg['version']}")
    except (EvidenceError, KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return Result(BLOCKED, f"registry coherence cannot be evaluated: {exc}")
    return Result(
        PASS, "all Actenon dependencies resolve to published, hash-matching files", evidence
    )


# --------------------------------------------------------------------------
# Matrix
# --------------------------------------------------------------------------


def evaluate(
    *,
    gate_files: Tree,
    tree: Tree,
    github: GitHub | None,
    pypi: Registry,
    candidate_sha: str,
    repository: str = "Actenon/actenon-airlock",
    expected_graph: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not SHA_RE.match(candidate_sha):
        raise AdmissionError(f"candidate sha {candidate_sha!r} is not a full commit id")
    # The rules come from the gate's own reviewed checkout, never from the
    # candidate, so a candidate cannot relax the criteria it is judged by.
    registry = load_registry(gate_files.read("release/gates.json"))
    frozen = check_frozen_definitions(registry, gate_files)
    if github is None:
        unauth = Result(BLOCKED, "no authenticated GitHub API access; CI evidence unavailable")
        ci, graph, acceptance = unauth, unauth, unauth
    else:
        ci = check_ci_prerequisites(registry, github, repository, candidate_sha)
        graph = check_dependency_graph(registry, github, tree, expected_graph or {})
        acceptance = check_frozen_acceptance(registry, github, tree, candidate_sha)
    coherence = check_registry_coherence(tree, pypi)

    gates: dict[str, dict[str, Any]] = {}
    for gate in registry["gates"]:
        if gate["definition"] == "MISSING":
            result = Result(UNDEFINED, "no committed acceptance condition; cannot be evaluated")
        else:
            result = acceptance
        row = {"definition": gate["definition"], **result.as_dict()}
        if gate["evidence"] == "frozen_external_acceptance":
            row["shared_evidence"] = "G28-G38 frozen programme run"
        gates[gate["id"]] = row

    prerequisites = {
        "frozen_definitions": frozen.as_dict(),
        "candidate_ci": ci.as_dict(),
        "dependency_graph": graph.as_dict(),
    }
    candidate_ok = all(p["status"] == PASS for p in prerequisites.values()) and all(
        g["status"] == PASS for g in gates.values()
    )
    if candidate_ok and coherence.status == PASS:
        overall = "RELEASE READY"
    elif candidate_ok:
        overall = "CANDIDATE READY"
    else:
        overall = "NOT READY"
    counts: dict[str, int] = {}
    for g in gates.values():
        counts[g["status"]] = counts.get(g["status"], 0) + 1
    return {
        "schema": "actenon-airlock/release-admission-report/v1",
        "repository": repository,
        "candidate_sha": candidate_sha,
        "overall_status": overall,
        "gate_counts": counts,
        "prerequisites": prerequisites,
        "release_only": {"registry_coherence": coherence.as_dict()},
        "gates": gates,
    }


def _token() -> str | None:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    gh = shutil.which("gh")
    if gh is None:
        return None
    proc = subprocess.run([gh, "auth", "token"], capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--candidate-sha", required=True, help="full 40-hex commit id")
    parser.add_argument(
        "--require",
        required=True,
        choices=STATUSES[1:],
        help="minimum status; the command exits 1 when the candidate falls short",
    )
    parser.add_argument("--repository", default="Actenon/actenon-airlock")
    parser.add_argument(
        "--expect-dependency",
        action="append",
        default=[],
        metavar="OWNER/REPO=SHA",
        help="require uv.lock to pin this exact candidate dependency commit",
    )
    parser.add_argument("--report", type=Path, help="also write the JSON report here")
    args = parser.parse_args(argv)

    expected: dict[str, str] = {}
    for item in args.expect_dependency:
        repo, _, rev = item.partition("=")
        if not SHA_RE.match(rev):
            parser.error(f"--expect-dependency {item!r} needs a full commit id")
        expected[repo] = rev
    token = _token()
    root = Path(__file__).resolve().parents[1]
    try:
        report = evaluate(
            gate_files=WorkingTree(root),
            tree=GitTree(root, args.candidate_sha),
            github=GitHubAPI(token) if token else None,
            pypi=PyPI(),
            candidate_sha=args.candidate_sha,
            repository=args.repository,
            expected_graph=expected,
        )
    except AdmissionError as exc:
        print(f"release admission cannot be evaluated: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2) + "\n"
    sys.stdout.write(text)
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    met = STATUSES.index(report["overall_status"]) >= STATUSES.index(args.require)
    print(
        f"overall status: {report['overall_status']} (required: {args.require})",
        file=sys.stderr,
    )
    return 0 if met else 1


if __name__ == "__main__":
    raise SystemExit(main())
