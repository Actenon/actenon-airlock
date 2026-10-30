from pathlib import Path

REPORT = Path("reports/incident-2041-03-04.md")


def test_report_exists_with_required_headings():
    text = REPORT.read_text()
    positions = [text.index(h) for h in ("## Timeline", "## Root cause", "## Customer impact")]
    assert positions == sorted(positions)
