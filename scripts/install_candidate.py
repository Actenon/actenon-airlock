#!/usr/bin/env python3
"""Install the candidate exactly as its uv.lock pins it, and record what pip installed (D9).

* **Registry-locked Actenon dependencies** (a release candidate):
  - export the lock with every sha256 (`uv export --frozen`);
  - install it with `pip install --require-hashes --no-deps`, so pip can install nothing but the
    locked files;
  - install Airlock itself with `--no-deps`;
  - then check that pip's report names exactly the locked wheels.
* **Git-locked dependencies** (pre-release candidates): the documented
  `pip install ".[test]"`, which resolves the locked commits from the pyproject pins.

Either way, pip's own installation report is written to ``--report``. The release-admission gate
reads that report from the CI artifacts and binds it to the approved sources.

``--index URL`` replaces PyPI for the Actenon packages only. The registry rehearsal uses it to
serve wheels built from the pinned commits, before anything is published; PyPI still serves
everything else.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
UV = "uv==0.11.25"


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def actenon_sources(lock: dict) -> dict[str, str]:
    """'git' or 'registry' for each Actenon dependency the lock pins."""
    out = {}
    for pkg in lock.get("package", []):
        name = _canonical(pkg.get("name", ""))
        if name.startswith("actenon-") and name != "actenon-airlock":
            source = pkg.get("source") or {}
            out[name] = "git" if "git" in source else "registry" if "registry" in source else "?"
    return out


def locked_wheels(lock: dict) -> dict[str, set[str]]:
    return {
        _canonical(pkg["name"]): {
            str(w.get("hash", "")).removeprefix("sha256:") for w in pkg.get("wheels", [])
        }
        for pkg in lock.get("package", [])
        if "registry" in (pkg.get("source") or {})
    }


def check_report(report: dict, lock: dict) -> list[str]:
    """Problems with pip's report: each locked Actenon wheel installed, nothing else."""
    wheels = locked_wheels(lock)
    wanted = {n for n, s in actenon_sources(lock).items() if s == "registry"}
    problems, seen = [], set()
    for item in report.get("install") or []:
        name = _canonical((item.get("metadata") or {}).get("name", ""))
        info = item.get("download_info") or {}
        digest = ((info.get("archive_info") or {}).get("hashes") or {}).get("sha256", "")
        if name in wheels and digest not in wheels[name]:
            problems.append(f"{name}: installed {digest[:12] or 'unhashed'}, not a locked wheel")
        seen.add(name)
    problems += [f"{name}: locked but not installed" for name in sorted(wanted - seen)]
    return problems


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default=sys.executable, help="interpreter to install into")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--index", help="index for the Actenon packages (rehearsal only)")
    args = parser.parse_args(argv)
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    sources = actenon_sources(lock)
    modes = set(sources.values())
    if modes == {"git"}:
        run([args.python, "-m", "pip", "install", "--report", str(args.report), ".[test]"])
        print(json.dumps({"mode": "git", "dependencies": sources}))
        return 0
    if modes != {"registry"}:
        print(f"refusing a mixed or unknown dependency source: {sources}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        tool = Path(tmp) / "uv-tool"
        run([sys.executable, "-m", "venv", str(tool)])
        run([str(tool / "bin" / "python"), "-m", "pip", "install", "--quiet", UV])
        requirements = Path(tmp) / "locked-requirements.txt"
        run([
            str(tool / "bin" / "uv"), "export", "--frozen", "--format", "requirements-txt",
            "--no-emit-project", "--extra", "test", "--output-file", str(requirements),
        ])  # fmt: skip
        index = []
        if args.index:
            host = urlparse(args.index).hostname or ""
            index = ["--index-url", args.index, "--extra-index-url", "https://pypi.org/simple"]
            index += ["--trusted-host", host] if host in {"127.0.0.1", "localhost"} else []
        run([
            args.python, "-m", "pip", "install", "--require-hashes", "--no-deps",
            "--report", str(args.report), *index, "-r", str(requirements),
        ])  # fmt: skip
    run([args.python, "-m", "pip", "install", "--no-deps", "."])
    problems = check_report(json.loads(args.report.read_text()), lock)
    for problem in problems:
        print(f"installed artifact problem: {problem}", file=sys.stderr)
    print(json.dumps({"mode": "registry", "dependencies": sources, "problems": problems}))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
