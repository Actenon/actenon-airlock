"""The human-readable consequence report never claims more than the signed evidence."""

import json

import pytest
from test_guided_workflow import Project

from actenon_airlock.cli import main
from actenon_airlock.consequence_report import _diffstat, build_report, render_markdown
from actenon_airlock.synthetic_github import TOKEN

INDEPENDENT_OK = {
    "source": "test referee",
    "confirmed": True,
    "commit_sha": "c" * 40,
    "checks": {"file_bytes_match_approved_candidate": True},
}
INDEPENDENT_BAD = {**INDEPENDENT_OK, "confirmed": False,
                   "checks": {"file_bytes_match_approved_candidate": False}}  # fmt: skip


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield Project(tmp_path)


def published(project, *, lose_ack=False):
    sha = project.candidate()
    project.verified(sha)
    project.approve(sha)
    if lose_ack:
        world = project.world()
        world["lose_next_acknowledgement"] = True
        project.provider.write_text(json.dumps(world))
    return sha, project.publish(sha)


def test_unsettled_write_is_reported_unconfirmed(project):
    _, result = published(project)
    report = build_report(project.state, result["effect_id"])
    assert report["status"] == "UNCONFIRMED"
    assert report["airlock_readback"] is None
    assert any("NOT been settled" in item for item in report["uncertain"])
    assert "none yet" in render_markdown(report)


def test_readback_and_independent_confirmation(project):
    sha, result = published(project)
    assert project.reconcile(result["effect_id"]) == 0
    own = build_report(project.state, result["effect_id"])
    assert own["status"] == "CONFIRMED_BY_AIRLOCK_READBACK"
    assert own["airlock_readback"]["commit_sha"] == project.world()["head"]
    both = build_report(project.state, result["effect_id"], independent=INDEPENDENT_OK)
    assert both["status"] == "CONFIRMED"
    assert both["wanted"]["candidate_sha256"] == sha
    assert both["wanted"]["diffstat"] == [{"path": "app.py", "added": 1, "removed": 1}]
    assert both["authorised"]["path"] == "patches/fix.patch"
    assert both["sent"]["credential_released"] is True


def test_independent_disagreement_is_disputed_not_confirmed(project):
    _, result = published(project)
    assert project.reconcile(result["effect_id"]) == 0
    report = build_report(project.state, result["effect_id"], independent=INDEPENDENT_BAD)
    assert report["status"] == "DISPUTED"
    assert "NOT confirm" in " ".join(report["uncertain"])


def test_lost_acknowledgement_is_disclosed(project):
    _, result = published(project, lose_ack=True)
    assert result["status"] == "AMBIGUOUS"
    assert build_report(project.state, result["effect_id"])["status"] == "UNCONFIRMED"
    assert project.reconcile(result["effect_id"]) == 0
    report = build_report(project.state, result["effect_id"])
    assert any("acknowledgement" in item for item in report["uncertain"])
    assert any("exclusive-writer" in item for item in report["uncertain"])


def test_nothing_sent(project):
    report = build_report(project.state, None)
    assert report["status"] == "NOT_SENT" and report["sent"] is None


def test_tampered_journal_claims_nothing(project):
    _, result = published(project)
    project.reconcile(result["effect_id"])
    journal = project.state.receipts_path
    journal.write_bytes(journal.read_bytes().replace(b"COMMITTED", b"COMMITTEX", 1))
    report = build_report(project.state, result["effect_id"], independent=INDEPENDENT_OK)
    assert report["status"] == "EVIDENCE_INVALID"
    assert "wanted" not in report and "authorised" not in report


def test_report_contains_no_credential_or_patch_body(project):
    _, result = published(project)
    project.reconcile(result["effect_id"])
    report = build_report(project.state, result["effect_id"], independent=INDEPENDENT_OK)
    text = render_markdown(report) + json.dumps(report)
    assert TOKEN not in text
    assert "return a + b" not in text
    for heading in ("What the agent wanted", "What Airlock authorised", "What was actually sent",
                    "What GitHub confirmed", "What remains uncertain", "Inspect the signed evidence"):  # fmt: skip
        assert heading in text


def test_explain_command(project, tmp_path, capsys):
    _, result = published(project)
    common = ["explain", "--path", str(project.root), result["effect_id"]]
    assert main(common) == 3  # unconfirmed until readback
    project.reconcile(result["effect_id"])
    independent = tmp_path / "independent.json"
    independent.write_text(json.dumps(INDEPENDENT_OK))
    output = tmp_path / "CONSEQUENCE.md"
    capsys.readouterr()
    assert main([*common, "--independent", str(independent), "--output", str(output)]) == 0
    assert output.read_text().startswith("# Consequence report: CONFIRMED")
    capsys.readouterr()
    assert main([*common, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "CONFIRMED_BY_AIRLOCK_READBACK"


def test_diffstat_uses_hunk_lengths():
    tricky = (
        b"--- a/x.py\n+++ b/x.py\n@@ -1,3 +1,3 @@\n keep\n---- removed dashes\n"
        b"++++ added pluses\n keep\n--- a/y.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n"
    )
    assert _diffstat(tricky) == [
        {"path": "x.py", "added": 1, "removed": 1},
        {"path": "y.py", "added": 0, "removed": 1},
    ]
