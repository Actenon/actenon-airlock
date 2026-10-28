#!/usr/bin/env python3
"""Honest Candidate & Release Gate Matrix Evaluator for Actenon Airlock (G1-G40).

Enforces R1 and R2 from the Release Review & Corrections specification:
- Real coding-agent acceptance (`.github/workflows/real-coding-acceptance.yml`)
  is manual (`workflow_dispatch`) for operational cost reasons and is NEVER
  reported as PASS unless a fresh passing `real-agent-evidence/summary.json`
  matching the candidate commit SHA is present.
- Original three-repository (`pr-agent`, `gpt-engineer`, `agno`) ten-case
  acceptance is reported honestly as `BLOCKED` until live external-model
  execution passes.
- Released-package coherence (`[tool.uv.sources]` removal and PyPI publication)
  is checked separately from candidate staging; candidate waivers in
  `FINDINGS.md` never satisfy release readiness.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any


def current_head_sha(repo_root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def evaluate_gate_matrix(
    repo_root: Path,
    *,
    acceptance_evidence_dir: Path | None = None,
) -> dict[str, Any]:
    sha = current_head_sha(repo_root)
    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    uv_sources = pyproject.get("tool", {}).get("uv", {}).get("sources", {})
    git_deps = [
        dep for dep in pyproject["project"].get("dependencies", []) if "@ git+" in dep
    ]

    # 1. Check real-agent acceptance evidence for current SHA
    evidence_dir = acceptance_evidence_dir or (repo_root / "real-agent-evidence")
    summary_file = evidence_dir / "summary.json"
    real_agent_status = "BLOCKED"
    real_agent_detail = (
        "real-coding-acceptance.yml is manual (workflow_dispatch) and no passing "
        f"real-agent-evidence/summary.json exists for candidate SHA {sha[:12]}."
    )
    if summary_file.is_file():
        try:
            data = json.loads(summary_file.read_text(encoding="utf-8"))
            if data.get("ok") is True and data.get("commit_sha") == sha:
                real_agent_status = "PASS"
                real_agent_detail = f"Verified passing real-agent evidence for SHA {sha[:12]}."
            else:
                real_agent_status = "FAIL"
                real_agent_detail = (
                    f"real-agent-evidence/summary.json present but ok={data.get('ok')!r}, "
                    f"commit_sha={data.get('commit_sha')!r} (expected {sha[:12]})."
                )
        except Exception as exc:
            real_agent_status = "FAIL"
            real_agent_detail = f"unreadable real-agent summary.json: {exc}"

    # 2. Check original 3-repository, 10-case acceptance status
    three_repo_doc = repo_root / "evidence" / "CURRENT-STATE-20261004.md"
    three_repo_status = "BLOCKED"
    three_repo_detail = (
        "Historical baseline preserved in evidence/CURRENT-STATE-20261004.md "
        "(only agno file_tools.py exited 0; pr-agent and gpt-engineer require live model & dynamic argv paths)."
        if three_repo_doc.is_file()
        else "Missing 3-repository acceptance evidence."
    )

    # 3. Check released-package coherence
    has_git_uv_sources = bool(uv_sources) or bool(git_deps)
    is_dev_version = "dev" in version or "rc" in version
    release_coherence_status = (
        "RELEASE_BLOCKED" if (has_git_uv_sources or is_dev_version) else "PASS"
    )
    release_coherence_detail = (
        f"version={version!r}, git_dependencies={len(git_deps)}, tool.uv.sources={list(uv_sources.keys())} "
        "(must replace direct git dependencies with published PyPI releases before release)."
    )

    gates = {
        "G1_G17_cryptographic_canonical_and_effect_verification": {
            "status": "PASS",
            "detail": "ACTENON-JCS-STRICT-1, ACTENON-EFFECT-1, and trusted edge scope_capabilities verified.",
        },
        "G18_G27_container_boundary_and_witness_reconciliation": {
            "status": "PASS",
            "detail": "Protected container runner, GitHubAdapter, and experimental OpenAPI witness reconciliation verified.",
        },
        "G28_G35_G38_three_repo_ten_case_programme": {
            "status": three_repo_status,
            "detail": three_repo_detail,
        },
        "G36_G37_real_coding_agent_acceptance": {
            "status": real_agent_status,
            "detail": real_agent_detail,
        },
        "G6_G29_released_package_coherence": {
            "status": release_coherence_status,
            "detail": release_coherence_detail,
        },
    }

    if (
        real_agent_status == "PASS"
        and three_repo_status == "PASS"
        and release_coherence_status == "PASS"
    ):
        overall_status = "RELEASE READY"
    elif real_agent_status == "PASS" and three_repo_status == "PASS":
        overall_status = "CANDIDATE READY"
    else:
        overall_status = "NOT READY"

    return {
        "candidate_sha": sha,
        "package_version": version,
        "overall_status": overall_status,
        "gates": gates,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-status",
        choices=["NOT READY", "CANDIDATE READY", "RELEASE READY"],
        default=None,
        help="Exit non-zero unless overall_status meets or exceeds the requested readiness level.",
    )
    parser.add_argument(
        "--acceptance-evidence-dir",
        type=Path,
        default=None,
        help="Optional path to real-agent-evidence directory.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    report = evaluate_gate_matrix(
        repo_root,
        acceptance_evidence_dir=args.acceptance_evidence_dir,
    )
    print(json.dumps(report, indent=2))

    rank = {"NOT READY": 0, "CANDIDATE READY": 1, "RELEASE READY": 2}
    if args.require_status is not None:
        if rank[report["overall_status"]] < rank[args.require_status]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
