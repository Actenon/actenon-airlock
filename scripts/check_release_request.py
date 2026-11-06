#!/usr/bin/env python3
"""Refuse a release request whose version does not describe the candidate commit.

Reads pyproject.toml from the candidate commit object (never the working tree)
and exits non-zero unless the requested version equals the candidate's
version, is a final release, and the candidate has no direct URL dependencies.
The release-admission gate then decides readiness from authenticated evidence.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FINAL_RE = re.compile(r"^\d+\.\d+\.\d+$")


def problems(pyproject: bytes | None, requested: str) -> list[str]:
    if pyproject is None:
        return ["pyproject.toml is absent from the candidate commit"]
    try:
        project = tomllib.loads(pyproject.decode("utf-8"))["project"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError) as exc:
        return [f"pyproject.toml is unreadable: {exc}"]
    found = []
    version = project.get("version")
    if version != requested:
        found.append(f"requested {requested!r} but the candidate declares {version!r}")
    if not FINAL_RE.match(requested):
        found.append(f"{requested!r} is not a final MAJOR.MINOR.PATCH release")
    direct = [d for d in project.get("dependencies", []) if "@" in d]
    if direct:
        found.append(f"direct URL dependencies cannot be released: {direct}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    if not SHA_RE.match(args.candidate_sha):
        print("candidate sha must be a full 40-character commit id", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    shown = subprocess.run(
        ["git", "show", f"{args.candidate_sha}:pyproject.toml"], cwd=root, capture_output=True
    )
    found = problems(shown.stdout if shown.returncode == 0 else None, args.version)
    for problem in found:
        print(f"release request refused: {problem}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
