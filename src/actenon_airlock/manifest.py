"""Translate Scan evidence into exact Permit capabilities, without a second PDP."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from actenon_scan.authority import ResourceState, classify_http, extract_authority

SECRET_NAME = re.compile(r"token|secret|password|passwd|credential|api.?key|private.?key", re.I)
EXCLUDED = {
    ".git",
    ".airlock",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    "docs",
}


class AirlockError(RuntimeError):
    """A fail-closed user-facing error."""


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


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


def power(action: str, resource: str, transport: str) -> dict:
    return {"action": action, "resource": resource, "transport": transport}


def capability(entry: dict) -> str:
    # The target dimension is encoded into Permit's existing signed action scope.
    # No globs: Permit itself denies an unlisted action/resource/transport tuple.
    return "airlock." + digest(power(entry["action"], entry["resource"], entry["transport"]))


def source_fingerprint(root: Path) -> str:
    rows = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(p in EXCLUDED for p in rel.parts):
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise AirlockError("Source symlinks are unsupported")
        rows.append([str(rel), hashlib.sha256(path.read_bytes()).hexdigest()])
    return digest(rows)


def discover(root: Path, env: dict | None = None) -> dict:
    root = root.resolve()
    report = extract_authority(root, env=dict(os.environ if env is None else env))
    entries, blocked, config_names = [], [], set()
    for ev in report.evidence:
        location = {"file": ev.file, "line": ev.line, "end_line": ev.end_line, "col": ev.col}
        for src in ev.sources:
            if src.kind == "env" and not SECRET_NAME.search(src.name):
                config_names.add(src.name)
        issue = None
        transport = ""
        if ev.resource_state is not ResourceState.RESOLVED or not ev.resource:
            issue = "Unresolved or template authority remains blocked"
        elif not ev.action.startswith(("http.", "github.")):
            issue = "No broker adapter for this consequential effect"
        elif ev.action in {"http.request", "github.graphql"}:
            issue = "Dynamic methods and GraphQL mutations need explicit adapter support"
        elif ev.url:
            try:
                url = validate_url(ev.url)
                actual = classify_http(ev.method, url)
                if actual.action != ev.action or actual.resource != ev.resource:
                    issue = "Scan evidence and transport disagree"
                transport = origin(url) if ev.action.startswith("github.") else url
            except AirlockError:
                issue = "Unsafe or unsupported HTTP URL"
        elif ev.action.startswith("github."):
            transport = "https://api.github.com"
        else:
            issue = "No exact transport URL in structured evidence"
        if issue:
            # Never persist call text or unresolved expressions: these can contain credentials.
            blocked.append(
                {**location, "action": ev.action, "state": str(ev.resource_state), "reason": issue}
            )
        else:
            entries.append(
                {
                    **power(ev.action, ev.resource, transport),
                    "evidence": location,
                    "via": ev.via,
                    "confidence": ev.confidence,
                }
            )
    powers = {capability(e): power(e["action"], e["resource"], e["transport"]) for e in entries}
    return {
        "schema": "actenon-airlock/authority/v1",
        "source_digest": source_fingerprint(root),
        "files_analysed": report.files_analysed,
        "powers": sorted(powers.values(), key=canonical),
        "entries": entries,
        "blocked": blocked,
        "parse_errors": [
            {"file": e["file"], "reason": "Source could not be parsed"} for e in report.parse_errors
        ],
        "config_names": sorted(config_names),
    }


def authority_diff(before: dict, after: dict) -> dict:
    old = {canonical(p): p for p in before.get("powers", [])}
    new = {canonical(p): p for p in after.get("powers", [])}
    return {
        "schema": "actenon-airlock/diff/v1",
        "added": [new[k] for k in sorted(new.keys() - old.keys())],
        "removed": [old[k] for k in sorted(old.keys() - new.keys())],
        "blocked": after.get("blocked", []),
        "parse_errors": after.get("parse_errors", []),
        "runtime_status": "BLOCKED UNTIL APPROVED"
        if new.keys() - old.keys()
        else "APPROVED POWERS ONLY",
    }


def request_capability(
    current: dict, method: str, url: str, locations: list[dict]
) -> tuple[str, dict]:
    url = validate_url(url)
    http = classify_http(method, url)
    if not http.resource or http.state is not ResourceState.RESOLVED:
        raise AirlockError("Runtime authority could not be resolved")
    transport = origin(url) if http.action.startswith("github.") else url
    entry = power(http.action, http.resource, transport)
    blocked_sites = {(p["file"], p["line"], p["col"]) for p in current["blocked"]}
    sites = [e["evidence"] for e in current["entries"]] + current["blocked"]

    def contains(position, loc):
        if position["file"] != loc["file"] or position.get("col", -1) < 0:
            return False
        end_line = position.get("end_line", position["line"])
        end_col = position.get("end_col", position["col"] + 1)
        return (
            position["line"] <= loc["line"] <= end_line
            and (loc["line"] != position["line"] or loc["col"] >= position["col"])
            and (loc["line"] != end_line or loc["col"] < end_col)
        )

    for ev in current["entries"]:
        loc = ev["evidence"]
        if power(ev["action"], ev["resource"], ev["transport"]) != entry:
            continue
        if (loc["file"], loc["line"], loc["col"]) in blocked_sites:
            continue
        for position in locations:
            if not contains(position, loc):
                continue
            # Await bytecode can span a whole await expression. Accept it only
            # when the span identifies one effect callsite, including unresolved sites.
            candidates = {(s["file"], s["line"], s["col"]) for s in sites if contains(position, s)}
            if len(candidates) == 1:
                return capability(entry), {**entry, "evidence": loc}
    # A dynamic/unscanned call cannot inherit the authority of a static call.
    return "airlock.unresolved." + digest(entry), {**entry, "evidence": None}
