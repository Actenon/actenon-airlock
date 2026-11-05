#!/usr/bin/env python3
"""Gate 7 programme: three upstream repositories, ten real-agent cases.

Commands that never call a model or write to GitHub:

  fetch     clone the three upstream repositories (trusted preparation)
  register  resolve cases.json to full upstream ids (writes registry.json)
  images    build the Go and Node compute images from the frozen inputs
  prestate  prove each case starts failing and the upstream fix passes
  freeze    write the frozen identity a live run must match
  rehearse  run one case with the real Claude Code binary and a scripted model

``live`` runs one case with real inference. It requires a freeze, the case's
explicit owner-authorised amount and a supervisor-only credential file, and it
never retries.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate7_programme as programme  # noqa: E402

DEFAULT_CACHE = Path.home() / ".cache/actenon-airlock/gate7-upstream"


def _write_new(path: Path, value: dict) -> None:
    with path.open("x") as file:
        json.dump(value, file, indent=2)
        file.write("\n")


def cmd_images(args) -> int:
    with tempfile.TemporaryDirectory(prefix="airlock-gate7-node-") as tmp:
        context = programme.node_context(args.cache, Path(tmp))
        subprocess.run(
            ["docker", "build", "-q", "-t", "actenon-airlock-gate7-node:v1", str(context)],
            check=True,
        )
    subprocess.run(
        ["docker", "build", "-q", "-f", str(HERE / "images/Dockerfile.go"),
         "-t", "actenon-airlock-gate7-go:v1", str(HERE / "images")],
        check=True,
    )  # fmt: skip
    subprocess.run(
        ["docker", "build", "-q", "-f", str(HERE / "images/Dockerfile.python"),
         "-t", "actenon-airlock-gate7-python:v1", str(HERE / "images")],
        check=True,
    )  # fmt: skip
    return 0


def cmd_prestate(args) -> int:
    ids = args.case or [c["id"] for c in programme.load_cases()["cases"]]
    results = []
    for case_id in ids:
        result = programme.prestate(case_id, args.cache)
        results.append(result)
        print(
            json.dumps(
                {
                    "case": case_id,
                    "observed": result["observed"],
                    "expected": result["expected"],
                    "reference_passes": result["reference_passes"],
                    "hidden_absent": result["hidden_tests_absent_from_workspace"],
                    "valid": result["valid"],
                }
            ),
            flush=True,
        )
    if args.out:
        _write_new(args.out, {"schema": "actenon-airlock/gate7-prestate/v1", "cases": results})
    return 0 if all(r["valid"] for r in results) else 1


def _live_inputs(args, item: dict, frozen: dict) -> dict:
    """Every local check a live run needs before anything leaves the machine."""
    import gate7_agent as agent

    from actenon_airlock.credential_preflight import (
        CredentialRefused,
        authenticate_anthropic,
        read_credential_file,
        supervisor_anthropic_credential,
    )

    if not frozen["working_tree_clean"]:
        raise SystemExit("Refusing a live run from a dirty working tree")
    if args.config is None or json.loads(args.config.read_text()) != frozen:
        raise SystemExit("Frozen configuration drift; refusing the live run")
    expected = agent.run_usd(item)
    if args.authorized_usd != expected:
        raise SystemExit(
            f"{item['id']} needs the owner-authorised amount --authorized-usd {expected}"
        )
    try:
        key = supervisor_anthropic_credential(None, args.credential_file)
    except CredentialRefused as exc:
        raise SystemExit(f"Supervisor credential refused: {exc}") from None
    github = None
    if "consequence" in item:
        gate6 = agent._gate6()
        gate6.PATH_IN_REPO = item["consequence"]["path"]
        write = read_credential_file(args.github_credential_file)
        read = read_credential_file(args.readback_credential_file)
        if write == read:
            raise SystemExit("The referee's read-only token must differ from the write token")
        facts = json.loads(args.repo_facts.read_text())
        if set(facts) != set(gate6.FACT_FIELDS):
            raise SystemExit("Repository facts must name exactly: " + ", ".join(gate6.FACT_FIELDS))
        target = f"{facts['owner']}/{facts['repo']}@{facts['branch']}:{gate6.PATH_IN_REPO}"
        if args.authorize_github_write != target:
            raise SystemExit(f"Owner authorisation must be exactly {target}")
        pre = gate6.Referee(token=read).repository(facts)
        if not all(pre.values()):
            raise SystemExit(f"Repository facts do not match GitHub; nothing was approved: {pre}")
        github = {"facts": facts, "write_token": write, "read_token": read}
    if authenticate_anthropic(key, frozen["model"])["outcome"] != "authenticated":
        raise SystemExit("Anthropic credential pre-flight failed; nothing was dispatched")
    return {"key": key, "github": github}


def cmd_run(args, *, live: bool) -> int:
    import os

    import gate7_agent as agent

    os.environ.pop("ANTHROPIC_API_KEY", None)
    os.environ.pop("GITHUB_TOKEN", None)
    item, _ = programme.case(args.case)
    frozen = agent.identity()
    inputs = _live_inputs(args, item, frozen) if live else {"key": None, "github": None}
    out = args.out.resolve()
    if "consequence" in item:
        if args.mode != "protected":
            raise SystemExit(f"{args.case} runs in protected mode only")
        code = agent.consequence_run(
            args.case, out, args.cache, key=inputs["key"], github=inputs["github"],
            interactive=getattr(args, "interactive_approval", False),
        )  # fmt: skip
        recorded = json.loads((out / "result.json").read_text())
        recorded["identity"] = frozen
        (out / "result.json").write_text(json.dumps(recorded, indent=2, default=str) + "\n")
    else:
        started = agent.agent_run(args.case, args.mode, out, args.cache, key=inputs["key"])
        result = started["result"]
        result["identity"] = frozen
        (out / "result.json").write_text(json.dumps(result, indent=2, default=str) + "\n")
        agent.save_evidence(started["project"], out)
        code = 0 if result["verdict"] == "PASS" else 1
    result = json.loads((out / "result.json").read_text())
    print(json.dumps({k: result.get(k) for k in
                      ("case", "mode", "evidence_class", "agent_exit", "verdict", "verdict_reasons")}))  # fmt: skip
    return code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch")
    sub.add_parser("register")
    sub.add_parser("images")
    p = sub.add_parser("prestate")
    p.add_argument("--case", action="append")
    p.add_argument("--out", type=Path)
    p = sub.add_parser("report")
    p.add_argument("evidence", type=Path)
    p = sub.add_parser("freeze")
    p.add_argument("--out", type=Path, required=True)
    for name in ("rehearse", "live"):
        p = sub.add_parser(name)
        p.add_argument("case")
        p.add_argument("mode", choices=("baseline", "protected"))
        p.add_argument("--out", type=Path, required=True)
        if name == "rehearse":
            p.add_argument("--interactive-approval", action="store_true")
        else:
            p.add_argument("--config", type=Path, required=True)
            p.add_argument("--authorized-usd", required=True)
            p.add_argument("--credential-file", type=Path, required=True)
            p.add_argument("--github-credential-file", type=Path)
            p.add_argument("--readback-credential-file", type=Path)
            p.add_argument("--repo-facts", type=Path)
            p.add_argument("--authorize-github-write")
    args = parser.parse_args(argv)
    if args.command == "fetch":
        print(json.dumps(programme.fetch(args.cache), indent=2))
        return 0
    if args.command == "register":
        programme.REGISTRY_PATH.write_text(
            json.dumps(programme.register(args.cache), indent=2) + "\n"
        )
        return 0
    if args.command == "images":
        return cmd_images(args)
    if args.command == "prestate":
        return cmd_prestate(args)
    if args.command == "report":
        import gate7_report as report

        print(report.render(args.evidence))
        return 0
    if args.command == "freeze":
        import gate7_agent as agent

        frozen = agent.identity()
        if not frozen["working_tree_clean"]:
            raise SystemExit("Refusing to freeze a dirty working tree")
        _write_new(args.out, frozen)
        return 0
    return cmd_run(args, live=args.command == "live")


if __name__ == "__main__":
    raise SystemExit(main())
