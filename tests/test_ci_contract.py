"""The trusted CI contract in release/gates.json must match what CI actually runs.

Two of the credential-isolation tests were skipped in the integration job and were not in the
container job's file list, so they ran nowhere (NS-2). These checks keep the contract honest:
every test the integration job may skip, and every test the container job must pass, belongs to
a file the container job really runs.

The contract was first measured on a full-history clone, but the integration job checked out a
single commit, so the two documented-install pin tests skipped on every green CI run and the
release gate failed items 1-4 (NS-4). The integration job must check out full history.
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


def job_block(job: str) -> str:
    """The lines of one top-level job in ci.yml, up to the next job key."""
    lines = CI.splitlines()
    start = lines.index(f"  {job}:")
    end = next(
        (i for i in range(start + 1, len(lines)) if re.fullmatch(r"  [a-z][\w-]*:", lines[i])),
        len(lines),
    )
    return "\n".join(lines[start:end])


HISTORY_TESTS = (
    "tests.test_readme_install::test_the_repository_docs_pin_one_commit_that_installs_this_code",
    "tests.test_readme_install::test_an_older_product_commit_is_rejected",
)


def test_the_integration_job_has_the_history_its_required_tests_need():
    """These tests skip on a shallow clone, and the contract does not allow them to skip."""
    integration = job_block("integration")
    checkout = integration.split("actions/checkout@", 1)[1].split("\n      - ", 1)[0]
    assert re.search(r"^\s+fetch-depth: 0\s*$", checkout, re.M), (
        "the integration job checks out a shallow clone, so the documented-install pin tests "
        "skip on every CI run"
    )
    for report in REGISTRY["ci_prerequisites"]["junit"]:
        if report["artifact"].startswith("integration-python-"):
            assert not set(HISTORY_TESTS) & set(report["allowed_skips"])
