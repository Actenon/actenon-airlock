#!/usr/bin/env python3
"""Observe an acceptance runner from outside it.

The runner writes its own verdict before it returns, so a recorded ``runner_exit`` is
a self-report. The referee launches the runner as a child process, records the exit
status the operating system reports, hashes the evidence the runner produced, and
writes its record OUTSIDE the evidence directory so the runner cannot rewrite it.

    python referee.py --record REFEREE.json --out OUT -- RUNNER_ARGS...

The runner's own arguments follow ``--`` and must include the same ``--out``.
The child inherits only an allowlisted environment plus explicitly forwarded names;
the referee never reads, stores or prints a credential value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

EVIDENCE = ("result.json", "receipts.jsonl", "checkpoint.json", "public-key.json", "sink.json")
ALLOWED = ("HOME", "PATH", "TMPDIR", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST", "LANG")
# Forwarded by NAME only so the runner's own supervisor can read it; never recorded.
FORWARDED = ("ANTHROPIC_API_KEY",)


def _digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def observe(runner_args: list[str], out: Path, record: Path) -> dict:
    out, record = out.resolve(), record.resolve()
    if record.is_relative_to(out):
        raise SystemExit("The referee record must be outside the evidence directory")
    if (
        "--out" not in runner_args
        or Path(runner_args[runner_args.index("--out") + 1]).resolve() != out
    ):
        raise SystemExit("The runner must be given the same --out the referee observes")
    environment = {n: os.environ[n] for n in ALLOWED + FORWARDED if n in os.environ}
    started = time.time()
    process = subprocess.run([sys.executable, *runner_args], env=environment, check=False)
    finished = time.time()
    result_path = out / "result.json"
    try:
        self_reported = json.loads(result_path.read_text()).get("runner_exit_self_reported")
    except (OSError, ValueError):
        self_reported = None
    observation = {
        "schema": "actenon-airlock/acceptance-referee/v1",
        "runner": [Path(runner_args[0]).name, *runner_args[1:]],
        "runner_sha256": _digest(Path(runner_args[0])),
        "out": str(out),
        "started_at": started,
        "finished_at": finished,
        "observed_exit_code": process.returncode,
        "self_reported_runner_exit": self_reported,
        "self_report_matches": self_reported == process.returncode,
        "evidence_sha256": {name: _digest(out / name) for name in EVIDENCE},
    }
    with record.open("x") as stream:  # never overwrite an earlier observation
        json.dump(observation, stream, indent=2)
        stream.write("\n")
    return observation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("runner", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    runner = args.runner[1:] if args.runner[:1] == ["--"] else args.runner
    if not runner:
        raise SystemExit("Give the runner and its arguments after --")
    observation = observe(runner, args.out, args.record)
    print(json.dumps({k: observation[k] for k in ("observed_exit_code", "self_report_matches")}))
    return observation["observed_exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
