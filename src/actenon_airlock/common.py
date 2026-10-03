"""Canonical encoding and URL rules shared by discovery, adapters, and the broker."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import unquote, urlsplit

SECRET_NAME = re.compile(r"token|secret|password|passwd|credential|api.?key|private.?key", re.I)


class AirlockError(RuntimeError):
    """A fail-closed user-facing error."""


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def power(action: str, resource: str, transport: str) -> dict:
    return {"action": action, "resource": resource, "transport": transport}


def validate_url(url: str) -> str:
    """No userinfo, ambiguous paths, fragments, or credentials in query strings."""
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError as exc:
        raise AirlockError("Invalid HTTP URL") from exc
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise AirlockError("Only absolute HTTP(S) URLs without userinfo are supported")
    if p.fragment or any(ord(c) < 32 for c in url) or "\\" in url:
        raise AirlockError("Ambiguous HTTP URL")
    # Do not let transport normalization turn a reviewed path into another path.
    decoded = unquote(p.path)
    if decoded != p.path or "//" in p.path or any(s in {".", ".."} for s in p.path.split("/")):
        raise AirlockError("Encoded or ambiguous paths require explicit adapter support")
    if any(SECRET_NAME.search(k) for k in re.split(r"[=&]", p.query)[::2]):
        raise AirlockError("Credentials in URLs are forbidden; use brokered headers")
    host = p.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    if port is not None and (p.scheme, port) not in {("https", 443), ("http", 80)}:
        host += f":{port}"
    return f"{p.scheme}://{host}{p.path or '/'}" + (f"?{p.query}" if p.query else "")


def origin(url: str) -> str:
    p = urlsplit(validate_url(url))
    return f"{p.scheme}://{p.netloc}"
