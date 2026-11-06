"""Check that the README's install command works for someone who knows nothing else.

The README once pinned a branch that was later deleted, so the documented install failed for
every newcomer. This check fails if the README's install command:

* is missing, duplicated or not a ``git+https`` install of this repository;
* pins anything other than a full, immutable commit SHA;
* names a commit that is not in this checkout's history (needs a full-history checkout);
* with ``--install``: does not install in a fresh virtual environment with an empty HOME, or
  ``airlock doctor --json`` does not succeed afterwards.

It never publishes, tags or modifies anything.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = "https://github.com/Actenon/actenon-airlock.git"
INSTALL = re.compile(r'python -m pip install "git\+(?P<url>https://[^"@]+)@(?P<ref>[^"]+)"')
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")


def readme_install_refs(text: str) -> list[tuple[str, str]]:
    """Every ``(url, ref)`` pair the README tells a reader to pip-install."""
    return [(m["url"], m["ref"]) for m in INSTALL.finditer(text)]


def check_readme(text: str) -> str:
    """The pinned commit, or raise ``ValueError`` describing what a newcomer would hit."""
    refs = readme_install_refs(text)
    if len(refs) != 1:
        raise ValueError(f"expected exactly one documented install command, found {len(refs)}")
    url, ref = refs[0]
    if url != REPO_URL:
        raise ValueError(f"install command points at {url}, not {REPO_URL}")
    if not FULL_SHA.match(ref):
        raise ValueError(
            f"install command pins {ref!r}; pin a full 40-character commit SHA, not a branch or tag"
        )
    return ref


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)


def check_commit_in_history(sha: str) -> None:
    if _git("cat-file", "-e", f"{sha}^{{commit}}").returncode != 0:
        raise ValueError(f"{sha} is not a commit in this checkout (is the checkout shallow?)")
    if _git("merge-base", "--is-ancestor", sha, "HEAD").returncode != 0:
        raise ValueError(f"{sha} is not an ancestor of HEAD, so it is not merged history")


def install_and_doctor(sha: str) -> dict:
    """Run the exact README command in a fresh venv and HOME; return ``airlock doctor --json``."""
    with tempfile.TemporaryDirectory(prefix="airlock-readme-install-") as tmp:
        tmp_path = Path(tmp)
        home = tmp_path / "home"
        home.mkdir()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PIP_CONFIG_FILE": os.devnull,
        }
        venv = tmp_path / ".venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, env=env, cwd=tmp)
        python = venv / "bin" / "python"
        subprocess.run(
            [str(python), "-m", "pip", "install", f"git+{REPO_URL}@{sha}"],
            check=True,
            env=env,
            cwd=tmp,
        )
        doctor = subprocess.run(
            [str(venv / "bin" / "airlock"), "doctor", "--json"],
            check=True,
            env=env,
            cwd=tmp,
            capture_output=True,
            text=True,
        )
        return json.loads(doctor.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--install", action="store_true", help="also install it and run airlock doctor"
    )
    args = parser.parse_args(argv)
    try:
        sha = check_readme((ROOT / "README.md").read_text(encoding="utf-8"))
        check_commit_in_history(sha)
    except ValueError as exc:
        print(f"README install check FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"README install pins merged commit {sha}")
    if args.install:
        report = install_and_doctor(sha)
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
