#!/usr/bin/env python3
"""Release-admission gate for Actenon Airlock.

The owner's accepted release bar is the requirement when ``release_bar`` is in
``release/gates.json``. G1-G40 are still evaluated and reported, as superseded
history. Without that block the G1-G40 path applies as before.

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
* Bar items that happen outside GitHub (a real model, a live provider, other
  operators) need an owner record bound to the exact commit. Records are read
  from the gate's own reviewed checkout, never the candidate. A record says the
  owner reviewed that evidence; it does not make the evidence true.

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
import tarfile
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
BAR_EVIDENCE = {"candidate_ci", "owner_record", "registry_coherence", "accepted"}
BAR_RECORD_SCHEMA = "actenon-airlock/release-bar-record/v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
FAILED_CONCLUSIONS = {"failure", "cancelled", "timed_out", "action_required", "startup_failure"}
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
# Published Actenon artifacts are fetched only from PyPI's own file host.
PYPI_FILES = "https://files.pythonhosted.org/"
# Metadata an sdist build generates. Every other sdist member must be the approved source.
SDIST_GENERATED = re.compile(r"^(PKG-INFO|setup\.cfg|(.+/)?[^/]+\.egg-info/[^/]+)$")


class AdmissionError(Exception):
    """The registry or candidate cannot be evaluated; nothing may be admitted."""


class EvidenceError(Exception):
    """A specific piece of evidence is missing, malformed or untrusted."""


@dataclass
class Result:
    status: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    # The trusted CI run a PASS came from, so later checks read the same run's artifacts.
    run_id: int | None = None

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
    def source_archive(self, repo: str, sha: str) -> bytes: ...


class Registry(Protocol):
    def files(self, name: str, version: str) -> list[dict[str, Any]] | None: ...
    def download(self, url: str) -> bytes: ...


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

    def source_archive(self, repo: str, sha: str) -> bytes:
        """The gzipped tarball GitHub serves for exactly this commit."""
        return self._request(f"{self._api}/repos/{repo}/tarball/{sha}")


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

    def download(self, url: str) -> bytes:
        if not url.startswith(PYPI_FILES):
            raise EvidenceError(f"refusing to fetch an artifact from outside PyPI: {url}")
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                body = resp.read(MAX_ARTIFACT_BYTES + 1)
        except OSError as exc:
            raise EvidenceError(f"PyPI file unreachable: {url}: {exc}") from exc
        if len(body) > MAX_ARTIFACT_BYTES:
            raise EvidenceError(f"{url} exceeds {MAX_ARTIFACT_BYTES} bytes")
        return body


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
    scope = registry.get("recovered_scope") or {}
    if not scope.get("sha256") or [s.get("id") for s in scope.get("sections", [])] != list(
        "ABCDEF"
    ):
        raise AdmissionError("recovered_scope must pin the goal document and list sections A-F")
    for section in scope["sections"]:
        if section.get("evidence") is not None:
            raise AdmissionError(f"section {section['id']}: unknown evidence producer")
    bar = registry.get("release_bar")
    if bar is not None:
        items = bar.get("items")
        if (
            not bar.get("sha256")
            or not bar.get("accepted_on")
            or not isinstance(items, list)
            or [item.get("id") for item in items] != list(range(1, 11))
        ):
            raise AdmissionError("release_bar must pin its document and list items 1-10")
        for item in items:
            if item.get("evidence") not in BAR_EVIDENCE:
                raise AdmissionError(f"bar item {item['id']}: unknown evidence producer")
            if item.get("required_for") not in {"candidate", "release"}:
                raise AdmissionError(f"bar item {item['id']}: unknown level")
    _validate_registry_dependencies(registry)
    return registry


def _validate_registry_dependencies(registry: dict[str, Any]) -> None:
    """The owner-approved source of every registry dependency, reviewed onto main."""
    spec = registry.get("registry_dependencies")
    if spec is None:
        return
    jobs = registry.get("ci_prerequisites", {}).get("dependency_jobs", {})
    reports = spec.get("install_reports")
    if not isinstance(reports, list) or not reports:
        raise AdmissionError("registry_dependencies must name the CI install reports")
    for report in reports:
        if not (isinstance(report, dict) and report.get("artifact") and report.get("file")):
            raise AdmissionError("each install report needs an artifact and a file")
    packages = spec.get("packages")
    if not isinstance(packages, list):
        raise AdmissionError("registry_dependencies.packages must be a list")
    seen: set[str] = set()
    for pkg in packages:
        name = pkg.get("name", "")
        if not name.startswith("actenon-") or name in seen:
            raise AdmissionError(f"approved dependency {name!r} is not a unique Actenon package")
        seen.add(name)
        if pkg.get("repository") not in jobs:
            raise AdmissionError(f"{name}: approved repository has no reviewed CI contract")
        if not SHA_RE.match(str(pkg.get("source_commit", ""))):
            raise AdmissionError(f"{name}: approved source must be a full commit id")
        if not isinstance(pkg.get("version"), str) or not pkg["version"]:
            raise AdmissionError(f"{name}: approved version is missing")
        root = pkg.get("source_root")
        if not isinstance(root, str) or ".." in root.split("/") or root.startswith("/"):
            raise AdmissionError(f"{name}: source_root must be a relative directory")
        if root and not root.endswith("/"):
            raise AdmissionError(f"{name}: source_root must end with '/'")
        pinned = pkg.get("artifact_sha256")
        if pinned is not None and (
            not isinstance(pinned, list) or not pinned or not all(HEX64_RE.match(h) for h in pinned)
        ):
            raise AdmissionError(f"{name}: artifact_sha256 must list sha256 digests")


def check_recovered_scope(registry: dict[str, Any], tree: Tree) -> dict[str, Result]:
    """Each recovered A-F section is a mandatory candidate requirement.

    No section has an automated evidence producer yet, so each is BLOCKED even
    when the document matches its pin. A changed or missing document FAILs all.
    """
    spec = registry["recovered_scope"]
    text = tree.read(spec["path"])
    if text is None or hashlib.sha256(text).hexdigest() != spec["sha256"]:
        bad = Result(FAIL, f"{spec['path']} is missing or differs from its pinned sha256")
        return {s["id"]: bad for s in spec["sections"]}
    return {
        s["id"]: Result(
            BLOCKED,
            f"{s['title']} (goal lines {s['lines']}): no evidence producer is defined yet",
        )
        for s in spec["sections"]
    }


def _owner_record(item: int, gate_files: Tree, candidate_sha: str) -> Result:
    """One item's reviewed record, bound to this commit. Anything less does not pass."""
    path = f"release/bar-records/item-{item}.json"
    raw = gate_files.read(path)
    if raw is None:
        return Result(BLOCKED, f"no owner record at {path}")
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        return Result(FAIL, f"{path} is malformed")
    if (
        not isinstance(record, dict)
        or record.get("schema") != BAR_RECORD_SCHEMA
        or record.get("item") != item
    ):
        return Result(FAIL, f"{path} is not a record for item {item}")
    if record.get("candidate_sha") != candidate_sha:
        return Result(BLOCKED, f"{path} records another commit")
    if record.get("result") != PASS:
        return Result(FAIL, f"{path} records {record.get('result')!r}")
    evidence = record.get("evidence_path")
    data = gate_files.read(evidence) if isinstance(evidence, str) else None
    if data is None or hashlib.sha256(data).hexdigest() != record.get("evidence_sha256"):
        return Result(FAIL, f"{path} names evidence that is missing or differs from its hash")
    return Result(PASS, f"owner record for {candidate_sha}", [evidence])


def check_release_bar(
    registry: dict[str, Any], gate_files: Tree, candidate_sha: str, ci: Result, coherence: Result
) -> dict[int, tuple[dict[str, Any], Result]]:
    spec = registry["release_bar"]
    text = gate_files.read(spec["path"])
    if text is None or hashlib.sha256(text).hexdigest() != spec["sha256"]:
        bad = Result(FAIL, f"{spec['path']} is missing or differs from its pinned sha256")
        return {item["id"]: (item, bad) for item in spec["items"]}
    accepted = Result(PASS, f"accepted by the {spec['accepted_by']} on {spec['accepted_on']}")
    results = {}
    for item in spec["items"]:
        source = item["evidence"]
        if source == "owner_record":
            result = _owner_record(item["id"], gate_files, candidate_sha)
        else:
            result = {"candidate_ci": ci, "registry_coherence": coherence, "accepted": accepted}[
                source
            ]
        results[item["id"]] = (item, result)
    return results


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
    return Result(
        PASS, f"all required CI jobs passed in run {ci_run['id']}", evidence, run_id=ci_run["id"]
    )


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


def _dependency_ci(gh: GitHub, repo: str, rev: str, jobs: list[str]) -> Result | None:
    """None when every reviewed job passed at ``rev``; otherwise why not."""
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
                BLOCKED if check is None else FAIL, f"{repo}@{rev[:12]}: {job!r} is {state}"
            )
    if bad:
        return Result(FAIL, f"{repo}@{rev[:12]}: failing checks {sorted(set(bad))}")
    return None


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def registry_packages(lock: bytes | None) -> list[dict[str, Any]]:
    """Actenon packages the candidate locks from a package registry."""
    if lock is None:
        raise EvidenceError("uv.lock is absent from the candidate commit")
    try:
        data = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EvidenceError(f"uv.lock is malformed: {exc}") from exc
    return [
        pkg for pkg in data.get("package", [])
        if _canonical_name(str(pkg.get("name", ""))).startswith("actenon-")
        and "registry" in (pkg.get("source") or {})
    ]  # fmt: skip


def source_files(archive: bytes) -> dict[str, bytes]:
    """Regular files of a GitHub commit tarball, without its top-level directory."""
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar.getmembers():
                parts = member.name.split("/", 1)
                if member.isfile() and len(parts) == 2 and ".." not in parts[1].split("/"):
                    handle = tar.extractfile(member)
                    if handle is not None:
                        files[parts[1]] = handle.read()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise EvidenceError(f"source archive is unreadable: {exc}") from exc
    if not files:
        raise EvidenceError("source archive is empty")
    return files


def _metadata(text: bytes) -> tuple[str, str]:
    fields = {}
    for line in text.decode("utf-8", "replace").splitlines():
        if not line.strip():
            break
        key, _, value = line.partition(":")
        fields.setdefault(key.strip().lower(), value.strip())
    return _canonical_name(fields.get("name", "")), fields.get("version", "")


def wheel_problem(
    blob: bytes, source: dict[str, bytes], root: str, name: str, version: str
) -> str | None:
    """None when every payload file is the approved source, byte for byte."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
        names = [n for n in archive.namelist() if not n.endswith("/")]
    except zipfile.BadZipFile as exc:
        return f"not a valid wheel: {exc}"
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        return "wheel contains an unsafe path"
    infos = {n.split("/", 1)[0] for n in names if n.split("/", 1)[0].endswith(".dist-info")}
    if len(infos) != 1 or any(n.split("/", 1)[0].endswith(".data") for n in names):
        return "wheel must have exactly one .dist-info and no .data directory"
    info = infos.pop()
    meta = archive.read(f"{info}/METADATA") if f"{info}/METADATA" in names else b""
    if _metadata(meta) != (_canonical_name(name), version):
        return f"wheel metadata is not {name} {version}"
    payload = [n for n in names if not n.startswith(info + "/")]
    if not payload:
        return "wheel has no payload"
    for path in payload:
        if source.get(root + path) != archive.read(path):
            return f"{path} is not the approved source file {root + path}"
    tops = {p.split("/", 1)[0] for p in payload}
    dropped = sorted(
        path[len(root):] for path in source
        if path.startswith(root) and path.endswith(".py")
        and path[len(root):].split("/", 1)[0] in tops
        and path[len(root):] not in payload
        and "/tests/" not in "/" + path[len(root):]
    )  # fmt: skip
    if dropped:
        return f"approved source modules are missing from the wheel: {dropped[:3]}"
    return None


def sdist_problem(blob: bytes, source: dict[str, bytes], name: str, version: str) -> str | None:
    """None when every sdist member is the approved source or generated build metadata."""
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            members = tar.getmembers()
            if any(not (m.isfile() or m.isdir()) for m in members):
                return "sdist contains a link or special file"
            files = {}
            tops = set()
            for m in members:
                top, _, rest = m.name.partition("/")
                tops.add(top)
                if m.isfile():
                    if not rest or ".." in rest.split("/") or m.name.startswith("/"):
                        return "sdist contains an unsafe path"
                    handle = tar.extractfile(m)
                    files[rest] = handle.read() if handle else b""
    except (tarfile.TarError, OSError, EOFError) as exc:
        return f"not a valid sdist: {exc}"
    if len(tops) != 1:
        return "sdist must have exactly one top-level directory"
    if _metadata(files.get("PKG-INFO", b"")) != (_canonical_name(name), version):
        return f"sdist PKG-INFO is not {name} {version}"
    for path, data in files.items():
        if path in source:
            if source[path] != data:
                return f"{path} differs from the approved source"
        elif not SDIST_GENERATED.match(path):
            return f"{path} is not in the approved source"
    return None


class ProvenanceFailure(Exception):
    """Provenance evidence exists and contradicts the approved source: FAIL, never BLOCKED."""


def _installed_artifacts(
    registry: dict[str, Any], gh: GitHub, repo: str, sha: str, run_id: int
) -> tuple[dict[str, set[tuple[str, str]]], dict[str, set[str]]]:
    """What pip recorded installing, per Actenon package and per mandated CI report."""
    installed: dict[str, set[tuple[str, str]]] = {}
    per_report: dict[str, set[str]] = {}
    for spec in registry["registry_dependencies"]["install_reports"]:
        blob = _artifact_bytes(gh, repo, {"id": run_id}, spec["artifact"], sha)
        try:
            report = json.loads(_zip_member(blob, spec["file"]))
        except (EvidenceError, json.JSONDecodeError) as exc:
            raise ProvenanceFailure(f"{spec['artifact']}: no usable install report: {exc}") from exc
        if not isinstance(report, dict) or report.get("version") != "1":
            raise ProvenanceFailure(f"{spec['artifact']}: not a pip installation report")
        names = per_report.setdefault(spec["artifact"], set())
        for item in report.get("install") or []:
            name = _canonical_name(str((item.get("metadata") or {}).get("name", "")))
            if not name.startswith("actenon-") or name == "actenon-airlock":
                continue
            info = item.get("download_info") or {}
            digest = ((info.get("archive_info") or {}).get("hashes") or {}).get("sha256", "")
            installed.setdefault(name, set()).add((str(digest), str(info.get("url", ""))))
            names.add(name)
    return installed, per_report


def _locked_files(pkg: dict[str, Any]) -> dict[str, str]:
    """sha256 -> 'wheel' or 'sdist' for every file uv.lock pins for this package."""
    entries = [("wheel", w) for w in pkg.get("wheels", [])]
    if "sdist" in pkg:
        entries.append(("sdist", pkg["sdist"]))
    return {str(e.get("hash", "")).removeprefix("sha256:"): kind for kind, e in entries}


def _prove_package(
    rule: dict[str, Any],
    pkg: dict[str, Any],
    gh: GitHub,
    pypi: Registry,
    jobs: list[str],
    installed: set[tuple[str, str]],
    reports_missing: list[str],
) -> Result | None:
    """None when this registry package is proven; otherwise the first contradiction."""
    name, version = _canonical_name(pkg["name"]), pkg["version"]
    failed = _dependency_ci(gh, rule["repository"], rule["source_commit"], jobs)
    if failed is not None:
        return failed
    files = pypi.files(pkg["name"], version)
    if not files:
        return Result(FAIL, f"{name}=={version} is not published on PyPI")
    published = {(f.get("digests") or {}).get("sha256"): f for f in files}
    locked = _locked_files(pkg)
    if "wheel" not in locked.values():
        return Result(FAIL, f"{name} locks no wheel")
    if rule.get("artifact_sha256") is not None and set(locked) != set(rule["artifact_sha256"]):
        return Result(FAIL, f"{name}: locked artifacts are not the approved artifacts")
    source = source_files(gh.source_archive(rule["repository"], rule["source_commit"]))
    for digest, kind in sorted(locked.items()):
        entry = published.get(digest)
        if entry is None:
            return Result(FAIL, f"{name}: locked {kind} {digest[:12]} is not on PyPI")
        blob = pypi.download(str(entry.get("url", "")))
        if hashlib.sha256(blob).hexdigest() != digest:
            return Result(FAIL, f"{name}: PyPI served bytes that differ from {digest[:12]}")
        if kind == "wheel":
            problem = wheel_problem(blob, source, rule["source_root"], name, version)
        else:
            problem = sdist_problem(blob, source, name, version)
        if problem:
            commit = rule["source_commit"][:12]
            return Result(FAIL, f"{name}: {kind} is not built from {commit}: {problem}")
    if reports_missing:
        return Result(FAIL, f"{name}: CI reports {reports_missing} do not record installing it")
    wheels = {d for d, kind in locked.items() if kind == "wheel"}
    for digest, url in sorted(installed):
        if digest not in wheels:
            shown = digest[:12] or "an unhashed artifact"
            return Result(FAIL, f"{name}: CI installed {shown}, which is not a locked wheel")
        if not url.startswith(PYPI_FILES):
            return Result(FAIL, f"{name}: CI installed it from {url!r}, not from PyPI")
    return None


def _registry_provenance(
    registry: dict[str, Any],
    gh: GitHub,
    pypi: Registry,
    pkgs: list[dict[str, Any]],
    repo: str,
    sha: str,
    ci: Result,
) -> tuple[Result | None, dict[str, str], list[str]]:
    """Bind approved source commit -> published artifact -> locked hash -> CI install."""
    spec = registry.get("registry_dependencies") or {"packages": []}
    approved = {_canonical_name(p["name"]): p for p in spec.get("packages", [])}
    jobs = registry["ci_prerequisites"]["dependency_jobs"]
    covered: dict[str, str] = {}
    evidence: list[str] = []
    for pkg in pkgs:
        name = _canonical_name(pkg["name"])
        rule = approved.get(name)
        if rule is None:
            detail = f"{name} is locked from a registry but has no approved source on main"
            return Result(FAIL, detail), {}, evidence
        if pkg.get("version") != rule["version"]:
            detail = f"{name} is locked at {pkg.get('version')} but {rule['version']} is approved"
            return Result(FAIL, detail), {}, evidence
        covered[rule["repository"]] = rule["source_commit"]
    if ci.status != PASS or ci.run_id is None:
        detail = "installed artifacts cannot be checked until candidate CI passes"
        return Result(BLOCKED, detail), covered, evidence
    try:
        installed, per_report = _installed_artifacts(registry, gh, repo, sha, ci.run_id)
    except ProvenanceFailure as exc:
        return Result(FAIL, str(exc)), covered, evidence
    locked_names = {_canonical_name(p["name"]) for p in pkgs}
    for pkg in pkgs:
        name = _canonical_name(pkg["name"])
        rule = approved[name]
        missing = sorted(a for a, names in per_report.items() if name not in names)
        failed = _prove_package(
            rule, pkg, gh, pypi, jobs[rule["repository"]], installed.get(name, set()), missing
        )
        if failed is not None:
            return failed, covered, evidence
        evidence.append(
            f"{name}=={pkg['version']}: {rule['repository']}@{rule['source_commit']} -> "
            f"PyPI {sorted(d[:12] for d in _locked_files(pkg))} -> CI installed "
            f"{sorted(d[:12] for d, _ in installed.get(name, set()))}"
        )
    unlocked = sorted(set(installed) - locked_names)
    if unlocked:
        return (
            Result(FAIL, f"CI installed Actenon packages that are not locked: {unlocked}"),
            covered,
            evidence,
        )
    return None, covered, evidence


def check_dependency_graph(
    registry: dict[str, Any],
    gh: GitHub,
    tree: Tree,
    expected: dict[str, str],
    *,
    pypi: Registry | None = None,
    repo: str = "Actenon/actenon-airlock",
    sha: str = "",
    ci: Result | None = None,
) -> Result:
    """Every reviewed dependency repository must be locked and proven; nothing passes vacuously.

    A git pin is proven by the pinned commit's reviewed CI. A registry pin is proven by an
    approved source commit on main, its reviewed CI, PyPI files whose content is that source,
    and the CI reports of what the candidate actually installed.
    """
    required = registry["ci_prerequisites"]["dependency_jobs"]
    evidence: list[str] = []
    try:
        lock = tree.read("uv.lock")
        deps = git_dependencies(lock)
        pkgs = registry_packages(lock)
        pinned = {repo_: rev for _, repo_, rev in deps}
        for name, repo_, rev in deps:
            jobs = required.get(repo_)
            if jobs is None:
                return Result(FAIL, f"{name} comes from {repo_}, which has no reviewed CI contract")
            failed = _dependency_ci(gh, repo_, rev, jobs)
            if failed is not None:
                failed.evidence = evidence
                return failed
            evidence.append(f"{repo_}@{rev}: {len(jobs)} required jobs passed")
        if pkgs:
            if pypi is None:
                return Result(BLOCKED, "registry dependencies need PyPI access", evidence)
            failed, covered, proven = _registry_provenance(
                registry, gh, pypi, pkgs, repo, sha, ci or Result(BLOCKED, "no CI result")
            )
            evidence.extend(proven)
            if failed is not None:
                failed.evidence = evidence
                return failed
            for repo_, rev in covered.items():
                if repo_ in pinned:
                    return Result(FAIL, f"{repo_} is locked both from git and from a registry")
                pinned[repo_] = rev
        missing = sorted(set(required) - set(pinned))
        if missing:
            return Result(FAIL, f"reviewed dependencies are not locked: {missing}", evidence)
        for repo_, rev in sorted(expected.items()):
            if pinned.get(repo_) != rev:
                return Result(
                    FAIL,
                    f"{repo_} is locked at {pinned.get(repo_)} but the candidate graph expects {rev}",
                    evidence,
                )
    except EvidenceError as exc:
        return Result(BLOCKED, str(exc), evidence)
    return Result(
        PASS,
        f"{len(deps)} git and {len(pkgs)} registry dependencies are proven against reviewed sources",
        evidence,
    )


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
    recovered = check_recovered_scope(registry, gate_files)
    if github is None:
        unauth = Result(BLOCKED, "no authenticated GitHub API access; CI evidence unavailable")
        ci, graph, acceptance = unauth, unauth, unauth
    else:
        ci = check_ci_prerequisites(registry, github, repository, candidate_sha)
        graph = check_dependency_graph(
            registry, github, tree, expected_graph or {},
            pypi=pypi, repo=repository, sha=candidate_sha, ci=ci,
        )  # fmt: skip
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
        **{f"recovered_section_{k}": v.as_dict() for k, v in recovered.items()},
    }
    bar_report = None
    if "release_bar" in registry:
        bar = check_release_bar(registry, gate_files, candidate_sha, ci, coherence)
        at_level = lambda level: [r for item, r in bar.values() if item["required_for"] == level]  # noqa: E731
        foundation = [graph, *at_level("candidate")]
        changed_goal = any(r.status == FAIL for r in recovered.values())
        candidate_ok = not changed_goal and all(r.status == PASS for r in foundation)
        release_ok = candidate_ok and all(r.status == PASS for r in at_level("release"))
        bar_report = {
            "accepted_on": registry["release_bar"]["accepted_on"],
            "items": {
                str(number): {
                    "title": item["title"],
                    "required_for": item["required_for"],
                    **result.as_dict(),
                }
                for number, (item, result) in bar.items()
            },
        }
    else:
        candidate_ok = all(p["status"] == PASS for p in prerequisites.values()) and all(
            g["status"] == PASS for g in gates.values()
        )
        release_ok = candidate_ok and coherence.status == PASS
    if release_ok:
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
        "requirement": "release_bar" if bar_report else "G1-G40",
        "release_bar": bar_report,
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
