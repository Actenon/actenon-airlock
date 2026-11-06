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
import re
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
    "tests.test_guided_workflow::test_verification_runs_trusted_tests_in_a_contained_container",
    "tests.test_guided_workflow::test_emergency_stop_kills_a_running_protected_agent",
    "tests.test_protected::test_identical_inference_repeats_through_the_real_boundary",
    "tests.test_protected::test_lost_inference_reply_holds_its_retry_through_the_real_boundary",
    "tests.test_protect::test_protect_takes_a_task_to_a_reviewed_patch",
    "tests.test_protect::test_the_demo_runs_with_its_control_and_cleans_up",
    "tests.test_protect::test_the_live_test_passes_against_the_synthetic_provider",
    "tests.test_codex_container::test_real_codex_executes_edits_tests_and_continues",
    "tests.test_codex_container::test_real_codex_continues_with_documented_direct_callers",
    "tests.test_codex_container::test_real_codex_lost_ack_stays_held",
    "tests.test_codex_container::test_real_codex_budget_refusal_before_provider",
    "tests.test_codex_container::test_codex_executed_transport_attacks_have_working_controls",
    "tests.test_codex_container::test_codex_artifact_approved_creation_readback_and_lost_ack",
    "tests.test_claude_code_container::test_real_client_completes_tool_loop_inside_protected_mode",
    "tests.test_claude_code_container::test_every_model_request_carries_only_the_contract",
    "tests.test_claude_code_container::test_agent_tools_reach_no_credential_network_or_host",
    "tests.test_claude_code_container::test_candidate_capture_sees_the_edit_and_no_agent_state",
    "tests.test_claude_code_container::test_out_of_contract_output_from_a_compromised_client_is_refused",
    "tests.test_claude_code_container::test_a_tool_call_naming_an_external_action_grants_nothing",
    "tests.test_claude_code_container::test_provider_rate_limit_retries_as_a_new_call_with_the_real_client",
    "tests.test_claude_code_container::test_a_lost_reply_ends_the_real_client_without_a_second_dispatch",
    "tests.test_claude_code_container::test_supervisor_spend_bound_stops_the_real_client",
]
INDEPENDENT_TEST = (
    "tests.test_independent_container::test_owned_transport_controls_and_protected_boundary"
)


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
        self.gate_files: dict[str, bytes] = {
            path: (ROOT / path).read_bytes()
            for path in (
                "release/RELEASE_BAR.md",
                "release/recovered/ACTENON_WORK_EXECUTION_GOAL.md",
            )
        }
        self.candidate_files: dict[str, bytes] = {}
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
            {
                "protected-results.xml": junit({n: "passed" for n in DOCKER_TESTS}),
                "independent-boundary-results.xml": junit({INDEPENDENT_TEST: "passed"}),
            },
        )
        skipped = {n: "skipped" for n in [*DOCKER_TESTS, INDEPENDENT_TEST]}
        for py in ("3.11", "3.12"):
            self.github.add_artifact(
                self.ci_run,
                f"integration-python-{py}",
                {"test-results.xml": junit({**ordinary, **skipped})},
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
        # These positive controls cover the G1-G40 path, which applies without the bar.
        self.registry.pop("release_bar", None)
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
        tree = Files(
            {"pyproject.toml": self.pyproject, "uv.lock": self.lock, **self.candidate_files}
        )
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


def test_independent_boundary_skip_fails_mandatory_ci(world: World) -> None:
    run = world.ci_run
    world.github.run_artifacts[run["id"]] = [
        artifact
        for artifact in world.github.run_artifacts[run["id"]]
        if artifact["name"] != "protected-container-acceptance"
    ]
    world.github.add_artifact(
        run,
        "protected-container-acceptance",
        {
            "protected-results.xml": junit({n: "passed" for n in DOCKER_TESTS}),
            "independent-boundary-results.xml": junit({INDEPENDENT_TEST: "skipped"}),
        },
    )
    report = world.evaluate()
    assert report["prerequisites"]["candidate_ci"]["status"] == "FAIL"
    assert "skipped" in report["prerequisites"]["candidate_ci"]["detail"]


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


# --- the owner's accepted release bar ------------------------------------------


def record(world: World, number: int, *, result="PASS", sha=CANDIDATE, **changes) -> None:
    evidence = f"release/bar-records/item-{number}/evidence.json"
    data = b'{"reviewed": true}'
    world.gate_files[evidence] = data
    value = {
        "schema": gate.BAR_RECORD_SCHEMA,
        "item": number,
        "candidate_sha": sha,
        "result": result,
        "evidence_path": evidence,
        "evidence_sha256": hashlib.sha256(data).hexdigest(),
        **changes,
    }
    world.gate_files[f"release/bar-records/item-{number}.json"] = json.dumps(value).encode()


def item_status(report: dict[str, Any], item: int) -> str:
    return report["release_bar"]["items"][str(item)]["status"]


def test_committed_bar_matches_its_pin_and_records_the_owner_decision() -> None:
    registry = json.loads((ROOT / "release" / "gates.json").read_text())
    bar = registry["release_bar"]
    assert hashlib.sha256((ROOT / bar["path"]).read_bytes()).hexdigest() == bar["sha256"]
    assert bar["accepted_by"] == "owner" and bar["accepted_on"] == "2026-11-01"
    assert [item["id"] for item in bar["items"]] == list(range(1, 11))
    assert not (ROOT / "release" / "bar-records").exists()


def test_perfect_ci_alone_cannot_pass_the_bar(world: World) -> None:
    report = world.evaluate()
    assert report["overall_status"] == "NOT READY"
    assert report["requirement"] == "release_bar"
    assert [item_status(report, n) for n in (1, 2, 3, 4, 10)] == ["PASS"] * 5
    assert [item_status(report, n) for n in (5, 6, 7, 9)] == ["BLOCKED"] * 4
    assert item_status(report, 8) == "FAIL"


def test_every_candidate_record_reaches_candidate_ready_without_g_text(world: World) -> None:
    for item in (5, 6, 7):
        record(world, item)
    report = world.evaluate()
    assert report["overall_status"] == "CANDIDATE READY", report["release_bar"]
    assert report["gates"]["G1"]["status"] == "UNDEFINED"
    assert report["prerequisites"]["frozen_definitions"]["status"] == "BLOCKED"


@pytest.mark.parametrize("missing", [5, 6, 7])
def test_one_missing_record_keeps_the_candidate_not_ready(world: World, missing: int) -> None:
    for item in {5, 6, 7} - {missing}:
        record(world, item)
    report = world.evaluate()
    assert report["overall_status"] == "NOT READY"
    assert item_status(report, missing) == "BLOCKED"


def test_release_ready_needs_public_packages_and_independent_operators(world: World) -> None:
    world.make_release()
    for item in (5, 6, 7):
        record(world, item)
    assert world.evaluate()["overall_status"] == "CANDIDATE READY"
    record(world, 9)
    assert world.evaluate()["overall_status"] == "RELEASE READY"


def test_operators_alone_do_not_make_a_development_version_a_release(world: World) -> None:
    for item in (5, 6, 7, 9):
        record(world, item)
    report = world.evaluate()
    assert report["overall_status"] == "CANDIDATE READY"
    assert item_status(report, 8) == "FAIL"


@pytest.mark.parametrize(
    ("changes", "status"),
    [
        ({"sha": "b" * 40}, "BLOCKED"),
        ({"result": "FAIL"}, "FAIL"),
        ({"result": "pass"}, "FAIL"),
        ({"item": 6}, "FAIL"),
        ({"schema": "something-else"}, "FAIL"),
        ({"evidence_sha256": "0" * 64}, "FAIL"),
        ({"evidence_path": "release/bar-records/missing.json"}, "FAIL"),
        ({"evidence_path": None}, "FAIL"),
    ],
)
def test_a_record_that_does_not_hold_up_never_passes(world: World, changes, status) -> None:
    for item in (6, 7):
        record(world, item)
    record(world, 5, **changes)
    report = world.evaluate()
    assert item_status(report, 5) == status
    assert report["overall_status"] == "NOT READY"


def test_a_malformed_record_fails(world: World) -> None:
    world.gate_files["release/bar-records/item-5.json"] = b"{not json"
    assert item_status(world.evaluate(), 5) == "FAIL"


def test_a_candidate_cannot_supply_its_own_records(world: World) -> None:
    for item in (5, 6, 7):
        record(world, item)
    world.candidate_files = {k: v for k, v in world.gate_files.items() if "bar-records" in k}
    world.gate_files = {k: v for k, v in world.gate_files.items() if "bar-records" not in k}
    report = world.evaluate()
    assert report["overall_status"] == "NOT READY"
    assert [item_status(report, n) for n in (5, 6, 7)] == ["BLOCKED"] * 3


def test_a_changed_bar_fails_every_item(world: World) -> None:
    for item in (5, 6, 7, 9):
        record(world, item)
    world.gate_files["release/RELEASE_BAR.md"] = b"# A relaxed bar\n"
    report = world.evaluate()
    assert report["overall_status"] == "NOT READY"
    assert {item_status(report, n) for n in range(1, 11)} == {"FAIL"}


def test_failing_ci_blocks_even_with_every_record(world: World) -> None:
    for item in (5, 6, 7):
        record(world, item)
    world.github.checks[(REPO, CANDIDATE)][0]["conclusion"] = "failure"
    report = world.evaluate()
    assert report["overall_status"] == "NOT READY"
    assert item_status(report, 2) != "PASS"


def test_failing_dependency_ci_blocks_even_with_every_record(world: World) -> None:
    for item in (5, 6, 7):
        record(world, item)
    repo, rev = DEPS["actenon-scan"]
    world.github.checks[(repo, rev)][0]["conclusion"] = "failure"
    assert world.evaluate()["overall_status"] == "NOT READY"


def test_a_changed_goal_document_blocks_even_with_every_record(world: World) -> None:
    for item in (5, 6, 7):
        record(world, item)
    world.gate_files["release/recovered/ACTENON_WORK_EXECUTION_GOAL.md"] = b"relaxed scope\n"
    assert world.evaluate()["overall_status"] == "NOT READY"


def test_no_github_access_cannot_pass_the_bar(world: World) -> None:
    for item in (5, 6, 7):
        record(world, item)
    assert world.evaluate(github=None)["overall_status"] == "NOT READY"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda bar: bar.update(sha256=None),
        lambda bar: bar.update(accepted_on=None),
        lambda bar: bar["items"].pop(),
        lambda bar: bar["items"][4].update(evidence="self_reported_summary"),
        lambda bar: bar["items"][4].update(required_for="never"),
    ],
)
def test_a_malformed_bar_cannot_be_evaluated(world: World, mutate) -> None:
    mutate(world.registry["release_bar"])
    with pytest.raises(gate.AdmissionError):
        world.evaluate()


@pytest.mark.parametrize("module", ["test_claude_code_container", "test_codex_container"])
def test_every_agent_container_test_is_mandatory(module: str) -> None:
    """A Docker-only test that is not listed skips on integration and fails the gate."""
    registry = json.loads((ROOT / "release" / "gates.json").read_text())
    required = {
        node for spec in registry["ci_prerequisites"]["junit"] for node in spec["must_pass"]
    }
    source = (ROOT / "tests" / f"{module}.py").read_text()
    names = re.findall(r"^def (test_\w+)", source, re.MULTILINE)
    assert names and {f"tests.{module}::{name}" for name in names} <= required
