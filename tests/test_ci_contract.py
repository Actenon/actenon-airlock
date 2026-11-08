"""The trusted CI contract in release/gates.json must match what CI actually runs.

Two of the credential-isolation tests were skipped in the integration job and were not in the
container job's file list, so they ran nowhere (NS-2). These checks keep the contract honest:
every test the integration job may skip, and every test the container job must pass, belongs to
a file the container job really runs.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = json.loads((ROOT / "release" / "gates.json").read_text())
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def container_job_files() -> set[str]:
    """The test modules the container job passes to pytest, as dotted names."""
    files = set()
    for line in CI.splitlines():
        if "python -m pytest" in line and (
            "protected-results.xml" in line or "independent-boundary" in line
        ):
            files |= {f[:-3].replace("/", ".") for f in re.findall(r"tests/test_\w+\.py", line)}
    return files


def test_every_allowed_integration_skip_runs_in_the_container_job():
    files = container_job_files()
    assert files, "could not find the container job's pytest commands"
    for report in REGISTRY["ci_prerequisites"]["junit"]:
        if not report["artifact"].startswith("integration-python-"):
            continue
        orphans = sorted(n for n in report["allowed_skips"] if n.split("::")[0] not in files)
        assert not orphans, f"{report['artifact']}: allowed skips that no CI job runs: {orphans}"


def test_every_required_container_test_exists_and_is_run():
    files = container_job_files()
    for report in REGISTRY["ci_prerequisites"]["junit"]:
        for node in report["must_pass"]:
            module, _, name = node.partition("::")
            assert module in files, f"{node}: its module is not in the container job"
            source = ROOT / (module.replace(".", "/") + ".py")
            names = {
                n.name
                for n in ast.walk(ast.parse(source.read_text()))
                if isinstance(n, ast.FunctionDef)
            }
            assert name.split("[")[0] in names, f"{node}: no such test function"


def test_the_container_job_allows_no_skips():
    for report in REGISTRY["ci_prerequisites"]["junit"]:
        if report["artifact"] == "protected-container-acceptance":
            assert report["allowed_skips"] == []
