"""Every `airlock ...` command a newcomer is told to run is one the CLI accepts.

Commands are taken from the code blocks of the user-facing docs and from the next steps the
product itself prints, then parsed by the real argument parser (nothing is executed).
"""

from __future__ import annotations

import argparse
import re
import shlex
from pathlib import Path

import pytest

from actenon_airlock import demo
from actenon_airlock.cli import main

ROOT = Path(__file__).resolve().parents[1]
GUIDES = [
    "README.md",
    "CONTRIBUTING.md",
    "docs/getting-started.md",
    "docs/real-project.md",
    "docs/troubleshooting.md",
    "docs/security-model.md",
    "docs/golden-path.md",
]
FENCE = re.compile(r"^(~~~|```)")


class Parsed(BaseException):
    """Raised instead of running the command once it has parsed."""


def commands_in(text: str) -> list[str]:
    found, inside, pending = [], False, ""
    for raw in text.splitlines():
        if FENCE.match(raw.strip()):
            inside = not inside
            continue
        if not inside:
            continue
        line = pending + raw.strip()
        pending = ""
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        line = re.sub(r"\s+#.*$", "", line)
        for part in re.split(r"\s*(?:&&|\|)\s*", line):
            if part.startswith(("airlock ", "~/.airlock/bin/airlock ")):
                found.append(part.removeprefix("~/.airlock/bin/"))
    return found


def documented() -> list[tuple[str, str]]:
    out = []
    for name in GUIDES:
        for command in commands_in((ROOT / name).read_text(encoding="utf-8")):
            out.append((name, command))
    for command in commands_in("~~~\n" + demo.NEXT_STEP + "\n~~~"):
        out.append(("airlock demo's next step", command))
    return out


def test_the_guides_contain_the_golden_path():
    shown = {command.split()[1] for _, command in documented()}
    assert {"doctor", "demo", "protect"} <= shown


@pytest.mark.parametrize(("where", "command"), documented(), ids=lambda v: v[:60])
def test_documented_command_parses(where, command, monkeypatch):
    original = argparse.ArgumentParser.parse_args

    def parse_only(self, args=None, namespace=None):
        original(self, args, namespace)
        raise Parsed

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", parse_only)
    # Placeholders such as <sha256> or <id> stand for a value the reader fills in.
    argv = [re.sub(r"<[^>]+>", "1", arg) for arg in shlex.split(command)[1:]]
    try:
        main(argv)
    except Parsed:
        return
    except SystemExit as exc:
        pytest.fail(f"{where}: `{command}` is not accepted by the CLI (exit {exc.code})")
    pytest.fail(f"{where}: `{command}` did not parse")


LINK = re.compile(r"\]\((?!https?://|mailto:)([^)\s#]*)(?:#([^)\s]+))?\)")


def _anchors(path: Path) -> set[str]:
    return {
        re.sub(r"[^a-z0-9 -]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    }


@pytest.mark.parametrize("name", GUIDES)
def test_relative_links_and_anchors_resolve(name):
    source = ROOT / name
    broken = []
    for target, anchor in LINK.findall(source.read_text(encoding="utf-8")):
        path = (source.parent / target).resolve() if target else source
        if not path.exists():
            broken.append(target)
        elif anchor and path.suffix == ".md" and anchor not in _anchors(path):
            broken.append(f"{target}#{anchor}")
    assert not broken, f"{name}: {broken}"
