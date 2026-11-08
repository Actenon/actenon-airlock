#!/usr/bin/env python3
"""Rehearse the registry release path in CI before anything is published (D9).

A release candidate installs its Actenon dependencies from PyPI by locked sha256. Until they are
published, this rehearsal stands in for PyPI with the same artifacts and the same path:

``prepare``
  - Clone each git-locked Actenon dependency at its exact locked commit.
  - Build its wheel with ``SOURCE_DATE_EPOCH`` set to the commit time.
  - Write a PEP 503 index whose links carry each file's sha256, as PyPI's do.
  - Rewrite ``pyproject.toml`` so the dependencies are exact ``==`` registry pins.
  - The CI job then serves that index, runs ``uv lock`` against it and installs through
    ``scripts/install_candidate.py``, which takes the registry path.

``verify``
  Run the release-admission gate's own content checks (``wheel_problem``) on every built wheel
  against ``git archive`` of its commit.

Nothing is published, and nothing leaves the runner. This is rehearsal evidence, not release
evidence: the release candidate's own CI installs from PyPI.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = "build==1.2.2.post1"


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def git_locked(lock: dict) -> dict[str, dict[str, str]]:
    out = {}
    for pkg in lock.get("package", []):
        name = _canonical(pkg.get("name", ""))
        git = (pkg.get("source") or {}).get("git")
        if name.startswith("actenon-") and git:
            url, _, rev = git.partition("#")
            out[name] = {"url": url.split("?", 1)[0], "commit": rev, "version": pkg["version"]}
    return out


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def prepare(work: Path) -> int:
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    deps = git_locked(lock)
    if not deps:
        print("uv.lock has no git-locked Actenon dependencies to rehearse", file=sys.stderr)
        return 2
    files, simple = work / "index" / "files", work / "index" / "simple"
    files.mkdir(parents=True)
    simple.mkdir(parents=True)
    tool = work / "build-tool"
    subprocess.run([sys.executable, "-m", "venv", str(tool)], check=True)
    subprocess.run(
        [str(tool / "bin" / "python"), "-m", "pip", "install", "--quiet", BUILD], check=True
    )
    manifest = {}
    for name, dep in sorted(deps.items()):
        src = work / "src" / name
        git("clone", "--quiet", dep["url"], str(src))
        git("checkout", "--quiet", dep["commit"], cwd=src)
        epoch = git("log", "-1", "--format=%ct", dep["commit"], cwd=src).strip()
        before = set(files.iterdir())
        subprocess.run(
            [str(tool / "bin" / "python"), "-m", "build", "--wheel", "--outdir", str(files), str(src)],
            check=True, env={**os.environ, "SOURCE_DATE_EPOCH": epoch}, capture_output=True,
        )  # fmt: skip
        (built,) = set(files.iterdir()) - before
        digest = hashlib.sha256(built.read_bytes()).hexdigest()
        page = simple / name
        page.mkdir()
        page.joinpath("index.html").write_text(
            f'<a href="../../files/{built.name}#sha256={digest}">{built.name}</a>\n'
        )
        manifest[name] = {**dep, "wheel": built.name, "sha256": digest}
    simple.joinpath("index.html").write_text("".join(f'<a href="{n}/">{n}</a>\n' for n in manifest))
    pyproject = (ROOT / "pyproject.toml").read_text()
    for name, dep in manifest.items():
        pattern = re.compile(rf'"{re.escape(name)} @ git\+[^"]*@{dep["commit"]}"')
        pyproject, count = pattern.subn(f'"{name}=={dep["version"]}"', pyproject)
        if count != 1:
            print(f"{name}: expected one git pin in pyproject.toml, found {count}", file=sys.stderr)
            return 2
    (ROOT / "pyproject.toml").write_text(pyproject)
    (work / "rehearsal.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    return 0


def verify(work: Path) -> int:
    spec = importlib.util.spec_from_file_location(
        "gate", ROOT / "scripts" / "check_candidate_admission.py"
    )
    gate = importlib.util.module_from_spec(spec)
    sys.modules["gate"] = gate
    spec.loader.exec_module(gate)
    manifest = json.loads((work / "rehearsal.json").read_text())
    problems = {}
    for name, dep in manifest.items():
        src = work / "src" / name
        archive = subprocess.run(
            ["git", "archive", "--format=tar.gz", f"--prefix={name}/", dep["commit"]],
            cwd=src, check=True, capture_output=True,
        ).stdout  # fmt: skip
        source = gate.source_files(archive)
        roots = [
            r
            for r in ("", "src/", "python/")
            if any(p.startswith(r + name.replace("-", "_") + "/") for p in source)
        ]
        wheel = (work / "index" / "files" / dep["wheel"]).read_bytes()
        found = [gate.wheel_problem(wheel, source, r, name, dep["version"]) for r in roots] or [
            "no source root"
        ]
        problems[name] = None if None in found else found[0]
        print(
            f"{name} {dep['version']} @ {dep['commit'][:12]}: {problems[name] or 'PROVEN against its commit'}"
        )
    (work / "provenance.json").write_text(json.dumps(problems, indent=2) + "\n")
    return 1 if any(problems.values()) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args(argv)
    return prepare(args.work) if args.command == "prepare" else verify(args.work)


if __name__ == "__main__":
    raise SystemExit(main())
