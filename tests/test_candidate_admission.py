"""Adversarial tests for the release-admission gate (scripts/check_candidate_admission.py).

Every test starts from a world in which all evidence is genuine and then breaks
exactly one thing, so each rejection is attributable and the positive control
proves the gate has a real path to PASS.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = "c" * 40
OTHER = "d" * 40
REPO = "Actenon/actenon-airlock"
DEPS = {
    "actenon-protocol": ("Actenon/actenon-protocol", "1" * 40),
    "actenon-kernel": ("Actenon/actenon-kernel", "2" * 40),
    "actenon-scan": ("Actenon/actenon-scan", "3" * 40),
    "actenon-permit": ("Actenon/actenon-permit", "4" * 40),
}
DOCKER_TESTS = [
    "tests.test_github_container::test_actual_container_github_grant_and_denials",
    "tests.test_protected::test_same_contained_environment_runs_engineering_workflow_and_refuses_bypass",
]


def _load():
    path = ROOT / "scripts" / "check_candidate_admission.py"
    spec = importlib.util.spec_from_file_location("check_candidate_admission", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load()


class Files:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files

    def read(self, path: str) -> bytes | None:
        return self.files.get(path)


class FakePyPI:
    def __init__(self) -> None:
        self.published: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def files(self, name: str, version: str) -> list[dict[str, Any]] | None:
        return self.published.get((name, version))


class FakeGitHub:
    def __init__(self) -> None:
        self.checks: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.runs: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.run_jobs: dict[int, list[dict[str, Any]]] = {}
        self.run_artifacts: dict[int, list[dict[str, Any]]] = {}
        self.blobs: dict[int, bytes] = {}
        self.attested: set[bytes] = set()

    def check_runs(self, repo, sha):
        return copy.deepcopy(self.checks.get((repo, sha), []))

    def workflow_runs(self, repo, sha):
        return copy.deepcopy(self.runs.get((repo, sha), []))

    def jobs(self, repo, run_id):
        return copy.deepcopy(self.run_jobs.get(run_id, []))

    def artifacts(self, repo, run_id):
        return copy.deepcopy(self.run_artifacts.get(run_id, []))

    def download_artifact(self, repo, artifact_id):
        return self.blobs[artifact_id]

    def verify_attestation(self, repo, path, signer_workflow, sha):
        if signer_workflow != ".github/workflows/real-coding-acceptance.yml" or sha != CANDIDATE:
            return False, "wrong signer or source digest"
        ok = path.read_bytes() in self.attested
        return ok, "verified" if ok else "no attestation for these bytes"

    def add_artifact(self, run: dict[str, Any], name: str, members: dict[str, bytes], **kw):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            for member, data in members.items():
                archive.writestr(member, data)
        blob = buf.getvalue()
        artifact_id = 10_000 + len(self.blobs)
        self.blobs[artifact_id] = blob
        self.run_artifacts.setdefault(run["id"], []).append(
            {
                "id": artifact_id,
                "name": name,
                "expired": False,
                "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
                "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]},
                **kw,
            }
        )


def junit(outcomes: dict[str, str]) -> bytes:
    cases = []
    for node, outcome in outcomes.items():
        classname, name = node.split("::")
        body = {"passed": "", "skipped": "<skipped/>", "failed": "<failure/>"}[outcome]
        cases.append(f'<testcase classname="{classname}" name="{name}">{body}</testcase>')
    return (
        f'<testsuites><testsuite name="pytest">{"".join(cases)}</testsuite></testsuites>'.encode()
    )


def run_record(run_id: int, workflow: str, sha: str = CANDIDATE, **kw) -> dict[str, Any]:
    return {
        "id": run_id,
        "check_suite_id": run_id * 10,
        "head_sha": sha,
        "path": workflow,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        **kw,
    }


def check(name: str, suite: int, conclusion: str = "success", check_id: int = 1) -> dict[str, Any]:
    return {
        "id": check_id,
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "app": {"slug": "github-actions"},
        "check_suite": {"id": suite},
    }


class World:
    """A complete, genuine evidence set for CANDIDATE. Tests break one piece."""

    def __init__(self) -> None:
        self.registry = json.loads((ROOT / "release" / "gates.json").read_text())
        self.gate_files: dict[str, bytes] = {}
        self.pyproject = (
            b'[project]\nname = "actenon-airlock"\nversion = "0.1.0.dev0"\n'
            b'dependencies = ["actenon-scan @ git+https://github.com/Actenon/actenon-scan.git@'
            + DEPS["actenon-scan"][1].encode()
            + b'"]\n'
        )
        self.lock = "".join(
            f'[[package]]\nname = "{name}"\nversion = "1.0.0"\n'
            f'source = {{ git = "https://github.com/{repo}.git?rev={rev}#{rev}" }}\n\n'
            for name, (repo, rev) in DEPS.items()
        ).encode()
        self.github = FakeGitHub()
        self.pypi = FakePyPI()
        self.summary: dict[str, Any] = {}
        self.frozen = self.registry["frozen_external_acceptance"]["frozen_configuration"]
        self._ci()
        self._dependencies()
        self._acceptance()

    def _ci(self) -> None:
        prereq = self.registry["ci_prerequisites"]
        self.ci_run = run_record(100, prereq["candidate_workflow"])
        self.github.runs[(REPO, CANDIDATE)] = [self.ci_run]
        self.github.checks[(REPO, CANDIDATE)] = [
            check(name, self.ci_run["check_suite_id"], check_id=i)
            for i, name in enumerate(prereq["candidate_jobs"], start=1)
        ]
        ordinary = {"tests.test_broker::test_denies_unapproved": "passed"}
        self.github.add_artifact(
            self.ci_run,
            "protected-container-acceptance",
            {"protected-results.xml": junit({n: "passed" for n in DOCKER_TESTS})},
        )
        for py in ("3.11", "3.12"):
            self.github.add_artifact(
                self.ci_run,
                f"integration-python-{py}",
                {"test-results.xml": junit({**ordinary, **{n: "skipped" for n in DOCKER_TESTS}})},
            )

    def _dependencies(self) -> None:
        jobs = self.registry["ci_prerequisites"]["dependency_jobs"]
        for repo, rev in DEPS.values():
            self.github.checks[(repo, rev)] = [
                check(name, 1, check_id=i) for i, name in enumerate(jobs[repo], start=1)
            ]

    def _acceptance(self) -> None:
        spec = self.registry["frozen_external_acceptance"]
        self.acc_run = run_record(200, spec["workflow"], event="workflow_dispatch")
        self.github.runs[(REPO, CANDIDATE)].append(self.acc_run)
        self.github.run_jobs[200] = [
            {
                "name": spec["job"],
                "conclusion": "success",
                "steps": [{"name": s, "conclusion": "success"} for s in spec["required_steps"]],
            }
        ]
        self.config = {
            **self.frozen,
            "airlock_dependency_manifest_sha256": hashlib.sha256(self.pyproject).hexdigest(),
            "image_id": "sha256:" + "e" * 64,
            "image_platform": "linux/amd64",
        }
        self.summary = {
            "model": self.frozen["model"],
            "model_fixture": False,
            "model_digest": self.frozen["model_digest"],
            "source_head": self.frozen["source_head"],
            "launch_result": 3,
            "error": None,
            "original_source_unchanged": True,
            "protected_host_file_unchanged": True,
        }
        self.baseline = {"status": "PASS", "exit_status": 0}
        self.acceptance = {"after_tests": "passed", "local_commit": "abc123"}
        self.receipts = {"ok": True, "verified": 7}

    def publish_acceptance(self) -> None:
        def prereg(config: dict[str, Any], phase: str) -> dict[str, Any]:
            canonical = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
            return {
                "phase": phase,
                "configuration": config,
                "configuration_sha256": hashlib.sha256(canonical).hexdigest(),
            }

        base = prereg(self.config, "unprotected-baseline")
        prot = prereg(self.config, "protected")
        baseline = {"configuration_sha256": base["configuration_sha256"], **self.baseline}
        summary = {"matched_baseline_configuration_sha256": base["configuration_sha256"]}
        summary.update(self.summary)
        prefix = "actenon-airlock/actenon-airlock/"
        files = {
            "baseline-agent-evidence/preregistration.json": base,
            "baseline-agent-evidence/baseline-result.json": baseline,
            "real-agent-evidence/preregistration.json": prot,
            "real-agent-evidence/run-summary.json": summary,
            "real-agent-evidence/acceptance.json": self.acceptance,
            "real-agent-evidence/receipt-verification.json": self.receipts,
        }
        members = {prefix + k: json.dumps(v).encode() for k, v in files.items()}
        members["_temp/ollama.log"] = b"model runtime log"
        self.github.add_artifact(self.acc_run, "real-external-coding-agent", members)
        for path in self.registry["frozen_external_acceptance"]["attested_files"]:
            self.github.attested.add(members[prefix + path])

    def freeze_definitions(self) -> None:
        self.satisfy_recovered_sections()
        text = b"# G1-G40 frozen acceptance criteria (owner-supplied test fixture)\n"
        self.gate_files["release/G1-G40.frozen.md"] = text
        self.registry["frozen_definitions"]["sha256"] = hashlib.sha256(text).hexdigest()
        for g in self.registry["gates"]:
            if g["definition"] == "MISSING":
                g.update(definition="FROZEN", acceptance_condition="fixture condition")
                g["evidence"] = "frozen_external_acceptance"

    def satisfy_recovered_sections(self) -> None:
        """Stand-in for future A-F evidence producers in positive controls only."""
        self.gate_files["release/recovered/ACTENON_WORK_EXECUTION_GOAL.md"] = (
            ROOT / "release" / "recovered" / "ACTENON_WORK_EXECUTION_GOAL.md"
        ).read_bytes()
        self.recovered_pass = True

    def make_release(self) -> None:
        wheel = b"published wheel"
        digest = hashlib.sha256(wheel).hexdigest()
        self.pyproject = (
            b'[project]\nname = "actenon-airlock"\nversion = "1.0.0"\n'
            b'dependencies = ["actenon-scan>=1,<2"]\n'
        )
        self.config["airlock_dependency_manifest_sha256"] = hashlib.sha256(
            self.pyproject
        ).hexdigest()
        self.lock = (
            '[[package]]\nname = "actenon-scan"\nversion = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            f'wheels = [{{ url = "https://files/x.whl", hash = "sha256:{digest}" }}]\n'
        ).encode()
        self.pypi.published[("actenon-scan", "1.0.0")] = [{"digests": {"sha256": digest}}]

    def evaluate(self, **kw) -> dict[str, Any]:
        self.gate_files["release/gates.json"] = json.dumps(self.registry).encode()
        if getattr(self, "recovered_pass", False):
            passing = {k: gate.Result(gate.PASS, "fixture") for k in "ABCDEF"}
            original = gate.check_recovered_scope
            gate.check_recovered_scope = lambda registry, tree: (original(registry, tree), passing)[
                1
            ]
            try:
                return self._evaluate(**kw)
            finally:
                gate.check_recovered_scope = original
        return self._evaluate(**kw)

    def _evaluate(self, **kw) -> dict[str, Any]:
        tree = Files({"pyproject.toml": self.pyproject, "uv.lock": self.lock})
        return gate.evaluate(
            gate_files=Files(self.gate_files),
            tree=tree,
            github=kw.pop("github", self.github),
            pypi=self.pypi,
            candidate_sha=kw.pop("candidate_sha", CANDIDATE),
            **kw,
        )


@pytest.fixture
def world() -> World:
    return World()


# --- positive controls: the gate has an executable path to PASS -------------


def test_genuine_attested_evidence_reaches_candidate_ready(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    report = world.evaluate()
    assert report["overall_status"] == "CANDIDATE READY", report["prerequisites"]
    assert all(g["status"] == "PASS" for g in report["gates"].values())
    assert report["release_only"]["registry_coherence"]["status"] == "FAIL"


def test_published_release_with_genuine_evidence_reaches_release_ready(world: World) -> None:
    world.make_release()
    world.publish_acceptance()
    world.freeze_definitions()
    report = world.evaluate()
    assert report["overall_status"] == "RELEASE READY", report


# --- the registry as committed today ------------------------------------------


def test_committed_registry_keeps_programme_not_ready_even_with_perfect_evidence(
    world: World,
) -> None:
    world.publish_acceptance()
    report = world.evaluate()
    assert report["overall_status"] == "NOT READY"
    assert report["prerequisites"]["frozen_definitions"]["status"] == "BLOCKED"
    undefined = [gid for gid, g in report["gates"].items() if g["status"] == "UNDEFINED"]
    assert undefined == [f"G{n}" for n in [*range(1, 28), 39, 40]]
    for n in range(28, 39):
        assert report["gates"][f"G{n}"]["shared_evidence"] == "G28-G38 frozen programme run"


def test_committed_registry_lists_forty_mandatory_gates_once() -> None:
    registry = gate.load_registry((ROOT / "release" / "gates.json").read_bytes())
    assert [g["id"] for g in registry["gates"]] == [f"G{n}" for n in range(1, 41)]
    assert not any(g["definition"] == "FROZEN" for g in registry["gates"])
    # Statuses are computed from evidence; none may be written into the registry.
    assert not any("status" in g or "PASS" in json.dumps(g) for g in registry["gates"])


# --- self-asserted and foreign evidence ---------------------------------------


def test_fabricated_local_pass_report_is_ignored(world: World, tmp_path: Path) -> None:
    world.freeze_definitions()
    forged = {"ok": True, "commit_sha": CANDIDATE, "model_fixture": False}
    world.gate_files["real-agent-evidence/summary.json"] = json.dumps(forged).encode()
    world.gate_files["real-agent-evidence/run-summary.json"] = json.dumps(forged).encode()
    report = world.evaluate()
    assert report["gates"]["G36"]["status"] == "BLOCKED"
    assert report["overall_status"] == "NOT READY"


def test_unattested_evidence_is_rejected(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    world.github.attested.clear()
    report = world.evaluate()
    assert report["gates"]["G28"]["status"] == "FAIL"
    assert "provenance not verified" in report["gates"]["G28"]["detail"]


def test_report_from_another_commit_is_rejected(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    for run in world.github.runs[(REPO, CANDIDATE)]:
        if run["id"] == 200:
            run["head_sha"] = OTHER
    assert world.evaluate()["gates"]["G30"]["status"] == "BLOCKED"


def test_artifact_bound_to_another_commit_is_rejected(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    world.github.run_artifacts[200][0]["workflow_run"]["head_sha"] = OTHER
    report = world.evaluate()
    assert report["gates"]["G28"]["status"] == "BLOCKED"
    assert "not bound" in report["gates"]["G28"]["detail"]


def test_run_from_fork_or_other_workflow_is_rejected(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    world.acc_run["head_repository"] = {"full_name": "attacker/actenon-airlock"}
    world.github.runs[(REPO, CANDIDATE)][1] = world.acc_run
    assert world.evaluate()["gates"]["G28"]["status"] == "BLOCKED"


def test_untrusted_trigger_is_ignored_and_named(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    world.acc_run["event"] = "schedule"
    world.github.runs[(REPO, CANDIDATE)][1] = world.acc_run
    result = world.evaluate()["gates"]["G28"]
    assert result["status"] == "BLOCKED"
    assert "200 (schedule)" in result["detail"]


def test_tampered_artifact_bytes_are_rejected(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    artifact_id = world.github.run_artifacts[200][0]["id"]
    world.github.blobs[artifact_id] += b"\x00"
    report = world.evaluate()
    assert report["gates"]["G28"]["status"] == "BLOCKED"
    assert "do not match digest" in report["gates"]["G28"]["detail"]


def test_unauthenticated_evaluation_cannot_pass(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    report = world.evaluate(github=None)
    assert report["overall_status"] == "NOT READY"
    assert report["prerequisites"]["candidate_ci"]["status"] == "BLOCKED"


# --- real-model acceptance cannot be satisfied by fixtures or drift -----------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model_fixture", True),
        ("model", "qwen2.5-coder:7b"),
        ("model_digest", "0" * 64),
        ("source_head", "f" * 40),
        ("launch_result", 0),
        ("protected_host_file_unchanged", False),
    ],
)
def test_fixture_or_changed_model_or_agent_fails_frozen_acceptance(
    world: World, field: str, value: Any
) -> None:
    world.summary[field] = value
    world.publish_acceptance()
    world.freeze_definitions()
    report = world.evaluate()
    assert report["gates"]["G38"]["status"] == "FAIL"
    assert report["overall_status"] == "NOT READY"


@pytest.mark.parametrize(
    "key", ["model", "model_digest", "source_head", "temperature", "driver_sha256", "expected"]
)
def test_changed_frozen_configuration_invalidates_acceptance(world: World, key: str) -> None:
    world.config[key] = "changed"
    world.publish_acceptance()
    world.freeze_definitions()
    assert world.evaluate()["gates"]["G28"]["status"] == "FAIL"


def test_failed_matched_baseline_cannot_be_offset_by_protected_success(world: World) -> None:
    world.baseline = {"status": "FAIL", "exit_status": 1}
    world.publish_acceptance()
    world.freeze_definitions()
    assert "baseline did not pass" in world.evaluate()["gates"]["G28"]["detail"]


def test_failed_acceptance_run_is_reported_as_fail_not_blocked(world: World) -> None:
    world.acc_run["conclusion"] = "failure"
    world.github.runs[(REPO, CANDIDATE)][1] = world.acc_run
    world.freeze_definitions()
    report = world.evaluate()
    assert report["gates"]["G28"]["status"] == "FAIL"
    assert world.acc_run["html_url"] in report["gates"]["G28"]["evidence"]


def test_skipped_protected_phase_cannot_pass(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    steps = world.github.run_jobs[200][0]["steps"]
    steps[1]["conclusion"] = "skipped"
    assert world.evaluate()["gates"]["G28"]["status"] == "FAIL"


# --- unit tests alone never admit a candidate --------------------------------


def test_green_unit_tests_cannot_override_missing_real_agent_evidence(world: World) -> None:
    world.freeze_definitions()
    report = world.evaluate()
    assert report["prerequisites"]["candidate_ci"]["status"] == "PASS"
    assert report["prerequisites"]["dependency_graph"]["status"] == "PASS"
    assert report["gates"]["G28"]["status"] == "BLOCKED"
    assert report["overall_status"] == "NOT READY"


def test_unexpected_skip_fails_mandatory_ci(world: World) -> None:
    run = world.ci_run
    world.github.run_artifacts[run["id"]] = []
    world.github.add_artifact(
        run,
        "protected-container-acceptance",
        {"protected-results.xml": junit({DOCKER_TESTS[0]: "passed", DOCKER_TESTS[1]: "skipped"})},
    )
    for py in ("3.11", "3.12"):
        world.github.add_artifact(
            run,
            f"integration-python-{py}",
            {"test-results.xml": junit({n: "skipped" for n in DOCKER_TESTS})},
        )
    report = world.evaluate()
    assert report["prerequisites"]["candidate_ci"]["status"] == "FAIL"
    assert "skipped" in report["prerequisites"]["candidate_ci"]["detail"]


def test_skipped_ci_job_does_not_count_as_success(world: World) -> None:
    world.github.checks[(REPO, CANDIDATE)][3]["conclusion"] = "skipped"
    assert world.evaluate()["prerequisites"]["candidate_ci"]["status"] == "FAIL"


def test_same_job_name_from_another_workflow_is_rejected(world: World) -> None:
    rogue = run_record(300, ".github/workflows/rogue.yml")
    world.github.runs[(REPO, CANDIDATE)].append(rogue)
    world.github.checks[(REPO, CANDIDATE)].append(
        check("Package and lint", rogue["check_suite_id"], check_id=99)
    )
    assert world.evaluate()["prerequisites"]["candidate_ci"]["status"] == "FAIL"


@pytest.mark.parametrize("payload", [b"", b"<testsuites>", b"<testsuites/>"])
def test_malformed_or_empty_junit_fails_closed(world: World, payload: bytes) -> None:
    run = world.ci_run
    artifacts = world.github.run_artifacts[run["id"]]
    world.github.run_artifacts[run["id"]] = [
        a for a in artifacts if a["name"] != "protected-container-acceptance"
    ]
    world.github.add_artifact(
        run, "protected-container-acceptance", {"protected-results.xml": payload}
    )
    assert world.evaluate()["prerequisites"]["candidate_ci"]["status"] == "BLOCKED"


# --- dependency graph ----------------------------------------------------------


def test_changed_dependency_manifest_invalidates_acceptance(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    world.pyproject += b"# graph changed after the acceptance run\n"
    report = world.evaluate()
    assert report["gates"]["G28"]["status"] == "FAIL"
    assert "dependency manifest" in report["gates"]["G28"]["detail"]


def test_lock_must_match_expected_candidate_graph(world: World) -> None:
    report = world.evaluate(expected_graph={"Actenon/actenon-permit": "9" * 40})
    assert report["prerequisites"]["dependency_graph"]["status"] == "FAIL"


def test_failing_dependency_ci_blocks_candidate(world: World) -> None:
    repo, rev = DEPS["actenon-kernel"]
    world.github.checks[(repo, rev)][0]["conclusion"] = "failure"
    assert world.evaluate()["prerequisites"]["dependency_graph"]["status"] == "FAIL"


def test_unpinned_git_dependency_fails_closed(world: World) -> None:
    world.lock = (
        b'[[package]]\nname = "x"\nsource = { git = "https://github.com/a/b.git?branch=main" }\n'
    )
    assert world.evaluate()["prerequisites"]["dependency_graph"]["status"] == "BLOCKED"


# --- registry coherence (release only) ----------------------------------------


def test_candidate_staging_never_satisfies_registry_coherence(world: World) -> None:
    result = world.evaluate()["release_only"]["registry_coherence"]
    assert result["status"] == "FAIL"


def test_missing_published_artifact_blocks_release(world: World) -> None:
    world.make_release()
    world.pypi.published.clear()
    world.publish_acceptance()
    world.freeze_definitions()
    report = world.evaluate()
    assert report["release_only"]["registry_coherence"]["status"] == "FAIL"
    assert report["overall_status"] == "CANDIDATE READY"


def test_published_digest_mismatch_blocks_release(world: World) -> None:
    world.make_release()
    world.pypi.published[("actenon-scan", "1.0.0")] = [{"digests": {"sha256": "0" * 64}}]
    world.publish_acceptance()
    world.freeze_definitions()
    assert world.evaluate()["overall_status"] == "CANDIDATE READY"


# --- registry integrity --------------------------------------------------------


def test_changed_frozen_definitions_fail(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    world.gate_files["release/G1-G40.frozen.md"] += b"relaxed\n"
    report = world.evaluate()
    assert report["prerequisites"]["frozen_definitions"]["status"] == "FAIL"
    assert report["overall_status"] == "NOT READY"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r["gates"].pop(5),
        lambda r: r["gates"].append(dict(r["gates"][0])),
        lambda r: r["gates"][0].update(required_for=["release"]),
        lambda r: r["gates"][0].update(definition="PASS"),
        lambda r: r["gates"][29].update(acceptance_condition=None),
        lambda r: r.update(schema="v0"),
    ],
)
def test_malformed_registry_cannot_be_evaluated(world: World, mutate) -> None:
    mutate(world.registry)
    with pytest.raises(gate.AdmissionError):
        world.evaluate()


def test_absent_registry_cannot_be_evaluated() -> None:
    with pytest.raises(gate.AdmissionError):
        gate.evaluate(
            gate_files=Files({}),
            tree=Files({}),
            github=None,
            pypi=FakePyPI(),
            candidate_sha=CANDIDATE,
        )


def test_abbreviated_candidate_sha_is_refused(world: World) -> None:
    with pytest.raises(gate.AdmissionError):
        world.evaluate(candidate_sha="c" * 12)


# --- command line and CI contract ----------------------------------------------


def test_require_threshold_is_mandatory(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        gate.main(["--candidate-sha", CANDIDATE])
    assert exc.value.code == 2
    assert "--require" in capsys.readouterr().err


def test_not_ready_exits_non_zero(monkeypatch, world: World) -> None:
    report = world.evaluate()
    monkeypatch.setattr(gate, "evaluate", lambda **_: report)
    monkeypatch.setattr(gate, "GitTree", lambda root, sha: Files({}))
    monkeypatch.setattr(gate, "_token", lambda: None)
    assert report["overall_status"] == "NOT READY"
    assert gate.main(["--candidate-sha", CANDIDATE, "--require", "CANDIDATE READY"]) == 1


def test_release_admission_workflow_enforces_explicit_threshold() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release-admission.yml").read_text()
    assert "scripts/check_candidate_admission.py" in workflow
    assert '--require "$REQUIRED"' in workflow
    assert "continue-on-error" not in workflow
    assert "RELEASE READY" in workflow


def test_acceptance_workflow_attests_the_evidence_it_produces() -> None:
    workflow = (ROOT / ".github" / "workflows" / "real-coding-acceptance.yml").read_text()
    registry = json.loads((ROOT / "release" / "gates.json").read_text())
    assert "actions/attest-build-provenance@" in workflow
    assert "id-token: write" in workflow and "attestations: write" in workflow
    for path in registry["frozen_external_acceptance"]["attested_files"]:
        assert path in workflow


# --- recovered A-F scope ---------------------------------------------------------


def test_committed_goal_document_matches_its_pin() -> None:
    registry = json.loads((ROOT / "release" / "gates.json").read_text())
    pinned = registry["recovered_scope"]["sha256"]
    doc = (ROOT / registry["recovered_scope"]["path"]).read_bytes()
    assert hashlib.sha256(doc).hexdigest() == pinned
    assert [s["id"] for s in registry["recovered_scope"]["sections"]] == list("ABCDEF")


def test_recovered_sections_block_even_with_perfect_g_evidence(world: World) -> None:
    world.publish_acceptance()
    world.freeze_definitions()
    world.recovered_pass = False
    world.gate_files["release/recovered/ACTENON_WORK_EXECUTION_GOAL.md"] = (
        ROOT / "release" / "recovered" / "ACTENON_WORK_EXECUTION_GOAL.md"
    ).read_bytes()
    report = world.evaluate()
    assert report["overall_status"] == "NOT READY"
    for section in "ABCDEF":
        assert report["prerequisites"][f"recovered_section_{section}"]["status"] == "BLOCKED"


def test_altered_goal_document_fails_every_section(world: World) -> None:
    world.gate_files["release/recovered/ACTENON_WORK_EXECUTION_GOAL.md"] = b"relaxed scope\n"
    report = world.evaluate()
    assert all(
        report["prerequisites"][f"recovered_section_{s}"]["status"] == "FAIL" for s in "ABCDEF"
    )


def test_recovered_section_cannot_claim_an_unknown_evidence_producer(world: World) -> None:
    world.registry["recovered_scope"]["sections"][4]["evidence"] = "self_reported_summary"
    with pytest.raises(gate.AdmissionError):
        world.evaluate()
