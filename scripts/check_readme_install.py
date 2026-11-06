"""Check that every documented install command works for someone who knows nothing else.

The README once pinned a branch that was later deleted, so the documented install failed for
every newcomer; another guide pinned a different, older branch. This check fails if:

* the README has no install command, or any documented install is not a ``git+https``
  install of this repository;
* any pins anything other than a full, immutable commit SHA, or they do not all pin the same one;
* that commit is not in this checkout's history (needs a full-history checkout);
* the code that commit installs differs from this checkout's (``src/``, ``pyproject.toml``,
  ``containers/``, ``MANIFEST.in``), so the docs would install an older product than they
  describe;
* with ``--install``: the exact documented pipx command fails in a fresh HOME, or
  ``airlock doctor --json`` does not succeed afterwards; with ``--demo`` also ``airlock demo``.

``--pin`` rewrites every documented install to the newest commit that changed installable
code (``--suggest`` only prints it). It never publishes, tags or pushes anything.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = "https://github.com/Actenon/actenon-airlock.git"
INSTALL = re.compile(
    r'(?P<tool>pipx install|pip install) "git\+(?P<url>https://[^"@]+)@(?P<ref>[^"]+)"'
)
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
# Everything that decides what an install of a commit contains.
INSTALLABLE = ("src", "pyproject.toml", "containers", "MANIFEST.in")
# Historical evidence quotes old commands verbatim and is never rewritten.
SKIP = ("release/", "acceptance/", "docs/evidence/")
PINNABLE = re.compile(r"(git\+https://github\.com/Actenon/actenon-airlock\.git@)[^\"\s]+")
# A guide that clones this repository checks out the same commit it installs.
CHECKOUT = re.compile(r"(git checkout )([0-9a-f]{40}|AIRLOCK_COMMIT)\b")


def documents(root: Path = ROOT) -> list[Path]:
    found = [root / "README.md", root / "CONTRIBUTING.md", *sorted((root / "docs").rglob("*.md"))]
    return [p for p in found if p.is_file() and not str(p.relative_to(root)).startswith(SKIP)]


def readme_install_refs(text: str) -> list[tuple[str, str]]:
    """Every ``(url, ref)`` pair the text tells a reader to install."""
    return [(m["url"], m["ref"]) for m in INSTALL.finditer(text)]


def _one_ref(refs: list[tuple[str, str]]) -> str:
    for url, ref in refs:
        if url != REPO_URL:
            raise ValueError(f"install command points at {url}, not {REPO_URL}")
        if not FULL_SHA.match(ref):
            raise ValueError(
                f"install command pins {ref!r}; pin a full 40-character commit SHA, "
                "not a branch, tag or placeholder"
            )
    pinned = {ref for _, ref in refs}
    if len(pinned) != 1:
        raise ValueError(f"documented installs pin different commits: {sorted(pinned)}")
    return pinned.pop()


def check_readme(text: str) -> str:
    """The commit one document pins, or raise ``ValueError``."""
    refs = readme_install_refs(text)
    if not refs:
        raise ValueError("expected a documented install command, found 0")
    return _one_ref(refs)


def check_documents(root: Path = ROOT) -> str:
    """The one commit every document pins, or raise ``ValueError`` naming the file."""
    check_readme((root / "README.md").read_text(encoding="utf-8"))
    refs = []
    for path in documents(root):
        text = path.read_text(encoding="utf-8")
        unparsed = len(PINNABLE.findall(text)) - len(readme_install_refs(text))
        if unparsed:
            raise ValueError(
                f"{path.relative_to(root)}: {unparsed} install reference(s) not in the "
                'documented form `pipx install "git+URL@COMMIT"`'
            )
        found = readme_install_refs(text)
        found += [(REPO_URL, m[2]) for m in CHECKOUT.finditer(text)]
        for url, ref in found:
            try:
                _one_ref([(url, ref)])
            except ValueError as exc:
                raise ValueError(f"{path.relative_to(root)}: {exc}") from None
            refs.append((url, ref))
    return _one_ref(refs)


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)


def check_commit_in_history(sha: str) -> None:
    if _git("cat-file", "-e", f"{sha}^{{commit}}").returncode != 0:
        raise ValueError(f"{sha} is not a commit in this checkout (is the checkout shallow?)")
    if _git("merge-base", "--is-ancestor", sha, "HEAD").returncode != 0:
        raise ValueError(f"{sha} is not an ancestor of HEAD, so it is not merged history")


def check_same_product(sha: str) -> None:
    changed = _git("diff", "--name-only", sha, "HEAD", "--", *INSTALLABLE).stdout.split()
    if changed:
        more = " …" if len(changed) > 5 else ""
        raise ValueError(
            f"the documented commit {sha[:12]} installs different code from this checkout "
            f"({', '.join(changed[:5])}{more}). Run: python scripts/check_readme_install.py --pin"
        )


def newest_product_commit() -> str:
    return _git("log", "-1", "--format=%H", "HEAD", "--", *INSTALLABLE).stdout.strip()


def pin(sha: str, root: Path = ROOT) -> list[Path]:
    """Point every documented install, including a placeholder, at ``sha``."""
    changed = []
    for path in documents(root):
        text = path.read_text(encoding="utf-8")
        new = CHECKOUT.sub(lambda m: m[1] + sha, PINNABLE.sub(lambda m: m[1] + sha, text))
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed.append(path)
    return changed


def _run(cmd, env, cwd, timings, label, timeout=1800):
    start = time.monotonic()
    result = subprocess.run(
        cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )
    timings[label] = round(time.monotonic() - start, 1)
    if result.returncode:
        tail = (result.stdout + result.stderr)[-2000:]
        raise RuntimeError(f"{label} failed with exit {result.returncode}:\n{tail}")
    return result


def clean_environment(home: Path) -> dict:
    """A fresh HOME and pipx location, with only what Docker needs to be found."""
    bin_dir = home / ".local" / "bin"
    env = {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(home),
        "PIPX_HOME": str(home / ".local" / "pipx"),
        "PIPX_BIN_DIR": str(bin_dir),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_CONFIG_FILE": os.devnull,
    }
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "TMPDIR"):
        if name in os.environ:
            env[name] = os.environ[name]
    if "DOCKER_CONFIG" in os.environ:
        env["DOCKER_CONFIG"] = os.environ["DOCKER_CONFIG"]
    elif (Path.home() / ".docker").is_dir():
        # Docker Desktop keeps its socket location in the real ~/.docker; reuse only that.
        env["DOCKER_CONFIG"] = str(Path.home() / ".docker")
    return env


def install_and_doctor(sha: str, *, demo: bool = False) -> dict:
    """Run the documented pipx install in a fresh HOME; return doctor's report and timings."""
    pipx = shutil.which("pipx")
    if not pipx:
        raise RuntimeError("pipx is not installed, so the documented install cannot be run")
    timings: dict[str, float] = {}
    with tempfile.TemporaryDirectory(prefix="airlock-documented-install-") as tmp:
        home = Path(tmp) / "home"
        home.mkdir()
        env = clean_environment(home)
        command = [pipx, "install", f"git+{REPO_URL}@{sha}"]
        _run(command, env, tmp, timings, "pipx install")
        doctor = _run(["airlock", "doctor", "--json"], env, tmp, timings, "airlock doctor")
        report = {"command": "pipx " + " ".join(command[1:]), "doctor": json.loads(doctor.stdout)}
        if demo:
            shown = _run(["airlock", "demo"], env, tmp, timings, "airlock demo")
            report["demo_claims_nothing"] = "claims nothing" in shown.stdout
            report["demo_tail"] = shown.stdout.splitlines()[-25:]
        report["timings_seconds"] = timings
        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--install", action="store_true", help="run the documented pipx install")
    parser.add_argument("--demo", action="store_true", help="with --install: also airlock demo")
    parser.add_argument("--suggest", action="store_true", help="print the commit to pin")
    parser.add_argument("--pin", action="store_true", help="rewrite the docs to that commit")
    args = parser.parse_args(argv)
    if args.suggest or args.pin:
        sha = newest_product_commit()
        print(sha)
        if args.pin:
            for path in pin(sha):
                print(f"pinned {path.relative_to(ROOT)}")
        return 0
    try:
        sha = check_documents()
        check_commit_in_history(sha)
        check_same_product(sha)
    except ValueError as exc:
        print(f"Documented install check FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"Every documented install pins {sha}, which installs this checkout's code")
    if args.install:
        try:
            report = install_and_doctor(sha, demo=args.demo)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"Documented install FAILED: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(report, indent=2))
        if not report["doctor"]["ok"] or report.get("demo_claims_nothing"):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
