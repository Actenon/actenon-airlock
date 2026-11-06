"""Short progress lines while an agent works; the full transcript goes to a log file.

The agent's container and the supervisor write to the terminal directly. While a run is
in progress everything written to stdout and stderr, by this process or a child, goes to
a private log instead, and only a few lines a person wants to read are shown: what the
agent is doing, what Airlock refused, and the agent's own last words, labelled as its
claim. Nothing here decides anything; it only changes what is shown.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import threading
from pathlib import Path

WIDTH = 72
_TEST_SUMMARY = re.compile(
    r"\b(\d+ (?:passed|failed|errors?|skipped)\b[^\n]*|FAIL\b[^\n]*|ok\s+\S+[^\n]*)"
)


def _short(text: str, width: int = WIDTH) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _path(value) -> str:
    return str(value or "").removeprefix("/workspace/")


class Progress:
    """Turns an agent's event stream into short lines. Unknown output is only logged."""

    def __init__(self) -> None:
        self.model_calls = 0
        self.refused = 0

    def feed(self, raw: bytes) -> list[str]:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line.strip():
            return []
        if line.startswith("{"):
            try:
                event = json.loads(line)
            except ValueError:
                return []
            return self._event(event) if isinstance(event, dict) else []
        if line.startswith("AIRLOCK ALLOW"):
            self.model_calls += 1
            return []
        if line.startswith("AIRLOCK DENY"):
            self.refused += 1
            reason = line.split(": ", 1)[-1].rsplit(" [", 1)[0]
            return [f"  refused   {_short(reason)}"]
        if line.startswith(("AIRLOCK PROTECTED MODE", "Protected workspace results")):
            return []
        if line.startswith("AIRLOCK"):
            return ["  " + _short(line, 100)]
        return []

    def _event(self, event: dict) -> list[str]:
        kind = event.get("type")
        if kind == "system" and event.get("subtype") == "init":
            return [f"  started   {event.get('model', 'the agent')} in the sealed container"]
        if kind == "assistant":
            content = (event.get("message") or {}).get("content") or []
            return [
                self._tool(b)
                for b in content
                if isinstance(b, dict) and b.get("type") == "tool_use"
            ]
        if kind == "user":
            out = []
            for block in (event.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    text = block.get("content")
                    if isinstance(text, list):
                        text = "\n".join(b.get("text", "") for b in text if isinstance(b, dict))
                    found = _TEST_SUMMARY.findall(str(text or ""))
                    if found:
                        out.append(f"            → {_short(found[-1], 60)}")
                    elif block.get("is_error"):
                        out.append("            → the command failed")
            return out
        if kind == "result":
            words = event.get("result") or ""
            lines = [f"  finished  after {event.get('num_turns', '?')} turn(s)"]
            if words:
                lines.append(f"  The agent says: {_short(words, 150)}")
                lines.append("  (its own words; what Airlock observed is below)")
            return lines
        return []

    @staticmethod
    def _tool(block: dict) -> str:
        name, given = block.get("name"), block.get("input") or {}
        if name == "Bash":
            what = given.get("description") or given.get("command", "").splitlines()[0:1]
            return f"  running   {_short(what if isinstance(what, str) else ' '.join(what))}"
        if name in ("Edit", "Write", "MultiEdit"):
            return f"  editing   {_path(given.get('file_path'))}"
        if name == "Read":
            return f"  reading   {_path(given.get('file_path'))}"
        if name in ("Glob", "Grep"):
            return f"  searching {_short(given.get('pattern', ''))}"
        return f"  using     {name}"


def _display(stream) -> tuple[io.TextIOBase, bool]:
    """Where progress is shown: the real terminal, or the caller's stream in tests."""
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        return stream, False
    return os.fdopen(os.dup(fd), "w", buffering=1, encoding="utf-8", errors="replace"), True


@contextlib.contextmanager
def live_progress(log_path: Path):
    """Send all output to `log_path` (owner-only) and show Progress lines instead."""
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    progress = Progress()
    shown_out, owned = _display(sys.stdout)
    for stream in (sys.stdout, sys.stderr):
        stream.flush()
    saved = os.dup(1), os.dup(2)
    reader, writer = os.pipe()
    os.dup2(writer, 1)
    os.dup2(writer, 2)
    pipe_text = os.fdopen(os.dup(writer), "w", buffering=1, encoding="utf-8", errors="replace")
    os.close(writer)
    original = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = pipe_text
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

    def pump() -> None:
        with os.fdopen(reader, "rb") as source, os.fdopen(fd, "wb") as log:
            for raw in source:
                log.write(raw)
                for line in progress.feed(raw):
                    shown_out.write(line + "\n")
                    shown_out.flush()

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    try:
        yield progress
    finally:
        pipe_text.flush()
        sys.stdout, sys.stderr = original
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for copy in saved:
            os.close(copy)
        pipe_text.close()
        thread.join(timeout=10)
        if owned:
            shown_out.close()
