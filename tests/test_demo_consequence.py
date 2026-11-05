"""The demo's receipt claims only what the evidence shows; any gap makes it claim nothing."""

import pytest

from actenon_airlock.demo_consequence import render
from actenon_airlock.github_consequence import ReviewedGitHubCreate

REVIEW = ReviewedGitHubCreate(repo_id=1, repo_node_id="R_x", owner="o", repo="r", branch="main",
                              expected_parent_sha="a" * 40, path="fixes/x.patch", message="m",
                              content_sha256="b" * 64)  # fmt: skip


def facts(**overrides):
    base = {
        "review_obj": REVIEW,
        "check": {"outcome": "PASS", "detail": "2 tests passed", "verdict": "TESTS_PASSED",
                  "checks": [{"counts": {"passed": 2}}]},
        "candidate": {"candidate_sha256": "b" * 64, "changes": [{"path": "calculator.py"}]},
        "not_granted": 0, "not_granted_examples": [], "signed_powers": ["github.contents.write"],
        "refusals": [("edited", {"status": "REFUSED"}, None), ("other", {"status": "REFUSED"}, None)],
        "puts_before_approved": 0, "puts_after": 1,
        "sent": {"status": "DISPATCHED_UNCONFIRMED"}, "effect": "e1", "unresolved_after_send": ["e1"],
        "replay": {"status": "REFUSED"}, "settled_exit": 0,
        "independent": {"confirmed": True},
        "final": {"unresolved_effects": [], "receipts": 9, "integrity_ok": True},
        "report_status": "CONFIRMED",
    }  # fmt: skip
    base.update(overrides)
    return base


def test_a_fully_evidenced_run_claims_success():
    lines, problems = render(facts())
    assert problems == []
    assert any("confirmed independently" in line for line in lines)


@pytest.mark.parametrize(
    "overrides",
    [
        {"refusals": [("edited", {"status": "SENT"}, None)]},
        {"puts_before_approved": 1},
        {"puts_after": 2},
        {"replay": {"status": "DISPATCHED_UNCONFIRMED"}},
        {"unresolved_after_send": []},
        {"settled_exit": 1},
        {"independent": {"confirmed": False}},
        {"report_status": "DISPUTED"},
    ],
    ids=["unrefused", "early-write", "two-writes", "replayed", "not-held", "unsettled",
         "independent-mismatch", "report-disputed"],
)  # fmt: skip
def test_any_missing_evidence_means_the_demo_claims_nothing(overrides):
    _, problems = render(facts(**overrides))
    assert problems
