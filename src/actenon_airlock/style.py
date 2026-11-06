"""Optional terminal colour. The words always carry the meaning; colour only helps scanning.

Colour is used only on an interactive terminal, never when NO_COLOR is set or TERM is
"dumb", and always when FORCE_COLOR is set (https://no-color.org).
"""

from __future__ import annotations

import os
import sys

CODES = {"good": "32", "bad": "31;1", "warn": "33", "head": "1", "dim": "2"}


def enabled(stream=None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    try:
        return stream.isatty() and os.environ.get("TERM", "") != "dumb"
    except (AttributeError, ValueError):
        return False


def paint(text: str, kind: str, stream=None) -> str:
    """``text`` in the colour for ``kind`` when colour is on; otherwise ``text`` unchanged."""
    if kind not in CODES or not enabled(stream):
        return text
    return f"\033[{CODES[kind]}m{text}\033[0m"
