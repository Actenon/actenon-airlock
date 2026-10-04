"""Translate Scan evidence into exact Permit capabilities, without a second PDP."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from actenon_scan.authority import ResourceState, extract_authority

from .adapters import adapter_for, http_candidates
from .common import (
    SECRET_NAME,
    AirlockError,
    canonical,
    digest,
    origin,
    power,
    validate_url,
)
from .model_constraints import endpoint as model_endpoint

__all__ = [
    "SECRET_NAME",
    "AirlockError",
    "authority_diff",
    "bind_runtime",
    "canonical",
    "capability",
    "digest",
    "discover",
    "origin",
    "power",
    "request_capability",
    "source_files",
    "source_fingerprint",
    "unadapted",
    "validate_url",
]

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


def capability(entry: dict) -> str:
    # The target dimension is encoded into Permit's existing signed action scope.
    # No globs: Permit itself denies an unlisted action/resource/transport tuple.
    return "airlock." + digest(power(entry["action"], entry["resource"], entry["transport"]))


def source_files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(p in EXCLUDED for p in rel.parts):
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise AirlockError("Source symlinks are unsupported")
        files.append(rel)
    return files


def source_fingerprint(root: Path, files: list[Path] | None = None) -> str:
    rows = []
    for rel in source_files(root) if files is None else files:
        path = root / rel
        if path.is_symlink() or not path.is_file():
            raise AirlockError("Scanned source was removed or replaced")
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
        adapter = adapter_for(ev.action)
        transport, issue = "", None
        if adapter is None:
            issue = "No Airlock adapter for this power kind; launch is refused"
        elif ev.resource_state is not ResourceState.RESOLVED or not ev.resource:
            issue = "Unresolved or template authority remains blocked"
        else:
            transport, issue = adapter.bind(ev)
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


def unadapted(current: dict) -> list[str]:
    """Scan powers no adapter can intercept; these cannot fail closed per call."""
    return sorted(
        {row["action"] for row in current["blocked"] if adapter_for(row["action"]) is None}
    )


def authority_diff(before: dict, after: dict) -> dict:
    old = {canonical(p): p for p in before.get("powers", [])}
    new = {canonical(p): p for p in after.get("powers", [])}
    old_model = before.get("protected_model", {})
    new_model = after.get("protected_model", old_model)
    try:
        model_expanded = bool(new_model) and (
            not old_model
            or new_model["provider"] != old_model["provider"]
            or model_endpoint(new_model) != model_endpoint(old_model)
            or not set(new_model["models"]).issubset(old_model["models"])
            or new_model["max_output_tokens"] > old_model["max_output_tokens"]
        )
    except (AirlockError, KeyError, TypeError):
        model_expanded = True
    return {
        "schema": "actenon-airlock/diff/v1",
        "added": [new[k] for k in sorted(new.keys() - old.keys())],
        "removed": [old[k] for k in sorted(old.keys() - new.keys())],
        "blocked": after.get("blocked", []),
        "parse_errors": after.get("parse_errors", []),
        "model_constraints": {"before": old_model, "after": new_model, "expanded": model_expanded},
        "runtime_status": "BLOCKED UNTIL APPROVED"
        if new.keys() - old.keys() or model_expanded
        else "APPROVED POWERS ONLY",
    }


def bind_runtime(current: dict, candidates, locations: list[dict]) -> tuple[str, dict]:
    """Bind an adapter's candidate powers to one resolved, scanned project callsite."""
    if not candidates:
        raise AirlockError("Runtime authority could not be resolved")
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

    for entry in candidates:
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
                found = {(s["file"], s["line"], s["col"]) for s in sites if contains(position, s)}
                if len(found) == 1:
                    return capability(entry), {**entry, "evidence": loc}
    # A dynamic/unscanned call cannot inherit the authority of a static call.
    first = candidates[0]
    return "airlock.unresolved." + digest(first), {**first, "evidence": None}


def request_capability(
    current: dict, method: str, url: str, locations: list[dict]
) -> tuple[str, dict]:
    return bind_runtime(current, http_candidates(method, url), locations)
