"""Gate 7 programme: pre-registration, scoring composition and refusal rules, offline.

No Docker, network or model is used here. Contained checks are replaced by a
deterministic stand-in so the composition of visible and hidden trees is tested
exactly; the real contained runs are recorded in the Gate 7 rehearsal evidence.
"""

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE7 = ROOT / "acceptance/gate7"
sys.path.insert(0, str(GATE7))
import gate7_agent as agent  # noqa: E402
import gate7_programme as programme  # noqa: E402

_spec = importlib.util.spec_from_file_location("gate7_run", GATE7 / "run.py")
gate7_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate7_run)

FROZEN_CASES = json.loads((GATE7 / "cases.json").read_text())
FROZEN_REGISTRY = json.loads((GATE7 / "registry.json").read_text())


# --------------------------------------------------------------------------
# The committed pre-registration
# --------------------------------------------------------------------------


def test_ten_cases_cover_each_capability_once_across_three_repositories():
    cases = FROZEN_CASES["cases"]
    assert [c["capability"] for c in cases] == list(range(1, 11))
    assert len({c["id"] for c in cases}) == 10
    assert set(FROZEN_CASES["repositories"]) == {"click", "path-to-regexp", "pflag"}
    assert {c["repository"] for c in cases} == set(FROZEN_CASES["repositories"])
    assert {m["toolchain"] for m in FROZEN_CASES["repositories"].values()} == {
        "python", "node", "go"
    }  # fmt: skip


def test_registry_pins_every_upstream_object_of_the_committed_cases():
    assert FROZEN_REGISTRY["schema"] == programme.REGISTRY_SCHEMA
    assert FROZEN_REGISTRY["cases_sha256"] == programme.sha256((GATE7 / "cases.json").read_bytes())
    full = re.compile(r"[0-9a-f]{40}\Z")
    for item in FROZEN_CASES["cases"]:
        reg = FROZEN_REGISTRY["cases"][item["id"]]
        assert full.match(reg["fix"]) and full.match(reg["base"]) and full.match(reg["base_tree"])
        listed = {*item.get("overlay_from_fix", []), *item["hidden_from_fix"],
                  *item["reference_from_fix"], *item.get("reference_tests_from_fix", [])}  # fmt: skip
        assert set(reg["fix_blobs"]) == listed
        assert all(full.match(b) for b in reg["fix_blobs"].values())
        issue = (GATE7 / "issues" / f"{item['id']}.md").read_bytes()
        assert reg["issue_sha256"] == programme.sha256(issue)


def test_issue_statements_never_name_the_upstream_fix():
    for item in FROZEN_CASES["cases"]:
        reg = FROZEN_REGISTRY["cases"][item["id"]]
        text = (GATE7 / "issues" / f"{item['id']}.md").read_text()
        assert reg["fix"][:7] not in text and reg["fix_subject"] not in text


def test_consequence_cases_are_protected_only_and_case_10_loses_its_acknowledgement():
    by_capability = {c["capability"]: c for c in FROZEN_CASES["cases"]}
    for n in (8, 9, 10):
        assert by_capability[n]["modes"] == ["protected"]
    assert by_capability[9]["consequence"]["acknowledgement"] == "kept"
    assert by_capability[10]["consequence"]["acknowledgement"] == "lost"
    assert by_capability[8]["provider_failure"]
    for n in range(1, 8):
        assert by_capability[n]["modes"] == ["baseline", "protected"]


# --------------------------------------------------------------------------
# A synthetic upstream and stand-in checks
# --------------------------------------------------------------------------


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _commit(repo, files, message):
    for path, text in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def world(tmp_path, monkeypatch):
    """One upstream repository whose fix makes lib.py say 'fixed'."""
    cache = tmp_path / "cache"
    repo = cache / "lib"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", "https://example.invalid/lib.git")
    _commit(
        repo,
        {"lib.py": "value = 'broken'\n", "tests/test_existing.py": "REQUIRES: value\n",
         "tests/test_shared.py": "REQUIRES: broken\n"},
        "base",
    )  # fmt: skip
    _commit(
        repo,
        {"lib.py": "value = 'fixed'\n", "tests/test_new.py": "REQUIRES: fixed\n",
         "tests/test_shared.py": "REQUIRES: fixed\n"},
        "Make lib say fixed",
    )  # fmt: skip
    cases = {
        "schema": "actenon-airlock/gate7-cases/v1",
        "model": "m",
        "prices": "1,1,1,1",
        "default_run_usd": "3",
        "repositories": {
            "lib": {"url": "https://example.invalid/lib.git", "licence": "MIT",
                    "toolchain": "python", "image": "stand-in"}  # fmt: skip
        },
        "checks": {"check": ["stand-in"]},
        "cases": [
            {"id": "c1", "capability": 1, "repository": "lib", "fix": "HEAD",
             "hidden_from_fix": ["tests/test_new.py", "tests/test_shared.py"],
             "reference_from_fix": ["lib.py"],
             "checks": {"visible": ["check"], "hidden": ["check"]},
             "expect_base": {"visible": "pass", "hidden": "fail"}, "modes": ["protected"]},
            {"id": "c2", "capability": 2, "repository": "lib", "fix": "HEAD",
             "hidden_from_fix": ["tests/test_new.py", "tests/test_shared.py"],
             "reference_from_fix": ["lib.py"],
             "reference_tests_from_fix": ["tests/test_new.py", "tests/test_shared.py"],
             "agent_tests_must_detect_base": True,
             "checks": {"visible": ["check"], "hidden": ["check"]},
             "expect_base": {"visible": "pass", "hidden": "fail"}, "modes": ["protected"]},
        ],
    }  # fmt: skip
    issues = tmp_path / "issues"
    issues.mkdir()
    for c in ("c1", "c2"):
        (issues / f"{c}.md").write_text("Make the library report that it is fixed.\n")
    monkeypatch.setattr(programme, "CASES_PATH", tmp_path / "cases.json")
    monkeypatch.setattr(programme, "REGISTRY_PATH", tmp_path / "registry.json")
    monkeypatch.setattr(programme, "ISSUES", issues)
    programme.CASES_PATH.write_text(json.dumps(cases))
    programme.REGISTRY_PATH.write_text(json.dumps(programme.register(cache)))
    calls = []

    def stand_in(image, tree, argv, toolchain):
        """Pass iff every REQUIRES word in every test file appears in lib.py."""
        calls.append(sorted(tree))
        words = [w for p, d in tree.items() if p.startswith("tests/")
                 for w in re.findall(rb"REQUIRES: (\w+)", d)]  # fmt: skip
        ok = all(w in tree.get("lib.py", b"") for w in words)
        return {"exit": 0 if ok else 1, "seconds": 0, "tail": []}

    monkeypatch.setattr(programme, "contained", stand_in)
    return {"cache": cache, "calls": calls}


def test_prestate_requires_a_failing_start_and_a_passing_upstream_fix(world):
    result = programme.prestate("c1", world["cache"])
    assert result["observed"] == {"visible": "pass", "hidden": "fail"}
    assert result["reference_passes"] and result["valid"]
    assert result["hidden_tests_absent_from_workspace"]


def test_workspace_has_no_history_no_fix_and_no_hidden_tests(world, tmp_path):
    work = tmp_path / "work"
    described = programme.prepare("c1", world["cache"], work)
    assert described["git_history"] == "none" and not (work / ".git").exists()
    assert (work / "lib.py").read_text() == "value = 'broken'\n"
    assert not (work / "tests/test_new.py").exists()
    assert (work / "ISSUE.md").exists()


def test_a_changed_issue_or_cases_file_is_refused(world, tmp_path):
    (programme.ISSUES / "c1.md").write_text("A different task.\n")
    with pytest.raises(programme.ProgrammeError, match="issue statement changed"):
        programme.prepare("c1", world["cache"], tmp_path / "w")
    programme.CASES_PATH.write_text(programme.CASES_PATH.read_text() + " ")
    with pytest.raises(programme.ProgrammeError, match="cases.json changed"):
        programme.load_registry()


def test_editing_the_visible_tests_cannot_pass_a_case(world):
    base = programme.base_tree("c1", world["cache"])
    cheat = {**base, "tests/test_existing.py": b"nothing required\n"}
    result = programme.score("c1", cheat, world["cache"])
    assert not result["conditions"]["source_changed"]
    assert not result["conditions"]["existing_tests_unmodified"]
    assert not result["passed"]


def test_a_superseded_test_may_change_and_is_scored_in_its_upstream_form(world):
    base = programme.base_tree("c1", world["cache"])
    fixed = {**base, "lib.py": b"value = 'fixed'\n", "tests/test_shared.py": b"REQUIRES: fixed\n"}
    result = programme.score("c1", fixed, world["cache"])
    assert result["superseded_by_hidden"] == ["tests/test_shared.py"]
    assert result["existing_tests_changed"] == []
    assert result["passed"]


def test_agent_written_tests_must_fail_on_the_original_source(world):
    base = programme.base_tree("c2", world["cache"])
    weak = {**base, "lib.py": b"value = 'fixed'\n", "tests/test_shared.py": b"REQUIRES: value\n"}
    assert not programme.score("c2", weak, world["cache"])["conditions"]["agent_tests_fail_on_base"]
    good = {**base, "lib.py": b"value = 'fixed'\n", "tests/test_shared.py": b"REQUIRES: fixed\n"}
    assert programme.score("c2", good, world["cache"])["passed"]


def test_links_refuse_a_tree(tmp_path):
    (tmp_path / "a").write_text("x")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    with pytest.raises(programme.ProgrammeError, match="link"):
        programme.read_tree(tmp_path)


def test_runtime_files_and_caches_are_not_scored(tmp_path):
    for name in ("ISSUE.md", "airlock_agent.py", ".tmp/go-build/x", "node_modules/m/i.js", "src/a"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("x")
    assert list(programme.read_tree(tmp_path)) == ["src/a"]


# --------------------------------------------------------------------------
# Verdicts, lost acknowledgements and live refusals
# --------------------------------------------------------------------------


def _result(**overrides):
    result = {
        "agent_exit": 0,
        "score": {"conditions": {"hidden_passed": True}, "passed": True,
                  "visible": {"checks": {"c": {"exit": 0}}},
                  "hidden": {"checks": {"c": {"exit": 0}}}},
        "evidence_integrity": {"integrity_ok": True},
        "inference": {"unconfirmed": 0},
        "accounting": {"estimated_microusd": 10, "bound_microusd": 100},
        "spend_bound_refusals": [],
    }  # fmt: skip
    result.update(overrides)
    return result


def test_verdicts_are_pre_registered():
    assert agent.verdict({}, _result()) == ("PASS", [])
    assert agent.verdict({}, _result(agent_exit=1))[0] == "FAIL"
    assert agent.verdict({}, _result(inference={"unconfirmed": 1}))[0] == "FAIL"
    over = _result(accounting={"estimated_microusd": 101, "bound_microusd": 100})
    assert agent.verdict({}, over)[0] == "FAIL"
    slow = _result()
    slow["score"]["hidden"]["checks"]["c"]["exit"] = 124
    assert agent.verdict({}, slow)[0] == "INCONCLUSIVE"


def test_a_spend_bound_case_passes_only_when_the_refusal_really_happened():
    item = {"provider_failure": "spend bound"}
    assert agent.verdict(item, _result())[0] == "INCONCLUSIVE"
    clean = {"credential_released": False, "execution_attempted": False}
    task_failed = _result(agent_exit=1, spend_bound_refusals=[clean])
    task_failed["score"]["passed"] = False
    assert agent.verdict(item, task_failed)[0] == "PASS"
    leaked = _result(spend_bound_refusals=[{**clean, "credential_released": True}])
    assert agent.verdict(item, leaked)[0] == "FAIL"


def test_lost_acknowledgement_delivers_the_create_and_discards_only_its_reply():
    seen = []

    def github(request):
        seen.append(request.method)
        return httpx.Response(201 if request.method == "PUT" else 200, json={})

    transport = agent.LoseAcknowledgement(httpx.MockTransport(github), "x/y.patch")
    with httpx.Client(transport=transport) as client:
        assert client.get("https://api.github.com/repos/o/r").status_code == 200
        with pytest.raises(httpx.ReadTimeout):
            client.put("https://api.github.com/repos/o/r/contents/x/y.patch", json={})
        assert (
            client.put("https://api.github.com/repos/o/r/contents/other", json={}).status_code
            == 201
        )
    assert seen == ["GET", "PUT", "PUT"] and transport.lost == 1


class _Args:
    config = None
    authorized_usd = "3"
    credential_file = None


def test_live_runs_refuse_a_dirty_tree_drift_and_the_wrong_amount(tmp_path):
    item = {"id": "c", "capability": 1}
    with pytest.raises(SystemExit, match="dirty"):
        gate7_run._live_inputs(_Args(), item, {"working_tree_clean": False})
    args = _Args()
    args.config = tmp_path / "freeze.json"
    args.config.write_text(json.dumps({"working_tree_clean": True, "x": 1}))
    with pytest.raises(SystemExit, match="drift"):
        gate7_run._live_inputs(args, item, {"working_tree_clean": True, "x": 2})
    args.authorized_usd = "2"
    with pytest.raises(SystemExit, match="--authorized-usd 3"):
        gate7_run._live_inputs(args, item, {"working_tree_clean": True, "x": 1})
