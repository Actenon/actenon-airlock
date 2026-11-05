"""The run receipt says only what was observed: never 'completed' because the agent said so."""

from pathlib import Path

import pytest

from actenon_airlock.protect import SPEND_BOUND, headline, report


def activity(*, refused=0, reasons=(), unconfirmed=0, spent=120_000, unresolved=()):
    return {
        "refused": refused,
        "refusal_reasons": list(reasons),
        "inference": {"dispatched": 5, "confirmed": 5 - unconfirmed, "unconfirmed": unconfirmed},
        "model_spend": {"estimated_microusd": spent},
        "integrity_ok": True,
        "receipts": 12,
        "unresolved_effects": list(unresolved),
    }


MANIFEST = {"changes": [{"status": "modified", "path": "calc.py"}], "candidate_sha256": "a" * 64}


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        ({"agent_exit": 0, "manifest": MANIFEST, "passed": True}, "your checks passed"),
        ({"agent_exit": 0, "manifest": MANIFEST, "passed": False}, "did not pass"),
        ({"agent_exit": 0, "manifest": MANIFEST, "passed": None}, "It is not verified"),
        ({"agent_exit": 0, "manifest": None, "passed": None}, "changed nothing"),
        ({"agent_exit": 1, "manifest": MANIFEST, "passed": None}, "did not finish (exit 1)"),
    ],
)
def test_the_headline_follows_the_evidence(facts, expected):
    text = headline(verdict="TESTS_FAILED: x", stopped_by_budget=False, **facts)
    assert expected in text
    assert "completed" not in text.lower()


def test_a_budget_stop_is_explained_and_never_reported_as_success(tmp_path, capsys):
    patch = tmp_path / "candidate.patch"
    patch.write_text("")
    report(MANIFEST, None, activity(refused=1, reasons=[SPEND_BOUND], spent=880_000), patch,
           agent_exit=0, spend_limit="$1.00", root=tmp_path)  # fmt: skip
    out = capsys.readouterr().out
    assert "Stopped early: Airlock's spend limit refused a model call" in out
    assert "about $0.88 of $1.00" in out and "$0.12 left" in out
    assert "reserves that call's worst-case cost" in out and "nothing was sent" in out
    assert "--max-run-usd" in out


def test_uncertain_calls_are_surfaced_not_hidden(tmp_path, capsys):
    patch = tmp_path / "candidate.patch"
    patch.write_text("")
    report(MANIFEST, "TESTS_PASSED: 3 tests passed", activity(unconfirmed=1), patch,
           agent_exit=0, spend_limit="$2.00", root=tmp_path, passed=True)  # fmt: skip
    out = capsys.readouterr().out
    assert "1 model call(s) got no confirmed answer" in out and "not retried" in out
    assert "External  none" in out
    assert Path(patch).name in out
