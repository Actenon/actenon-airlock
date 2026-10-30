"""Read-only, stopped-runtime inventory. Never migrates or releases an owner.

SQLite can write shared-memory files even on a read-only connection. Capture
regular files without opening the source database through SQLite, then inspect
only a disposable copy (including WAL). Operators must stop every supervisor:
a double capture detects changes, but is not an online atomic snapshot protocol.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
from contextlib import closing
from pathlib import Path

from actenon_protocol.effects import EFFECT_PROFILE, effect_identity

from .common import AirlockError, digest
from .evidence import verify_offline
from .state import verify_receipt_lines

FILES = (
    "public-key.json",
    "local/receipts.jsonl",
    "local/permit.sqlite3",
    "local/permit.sqlite3-wal",
    "local/permit.sqlite3-shm",
    "local/permit.sqlite3-journal",
)


def _capture(path: Path) -> dict[str, bytes | None]:
    for directory in (path, path / "local"):
        if directory.is_symlink():
            raise AirlockError("Inventory refuses symlinked state directories")
    captured = {}
    for name in FILES:
        try:
            fd = os.open(path / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            captured[name] = None
            continue
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise AirlockError("Inventory requires regular state files")
            captured[name] = stream.read()
    return captured


def _owners(captured: dict) -> list[dict]:
    if captured["local/permit.sqlite3"] is None:
        raise AirlockError("effect database is missing; absence is not proof of a fresh deployment")
    with tempfile.TemporaryDirectory(prefix="airlock-inventory-") as temporary:
        database = Path(temporary) / "permit.sqlite3"
        for suffix in ("", "-wal", "-journal"):
            content = captured["local/permit.sqlite3" + suffix]
            if content is not None:
                database.with_name(database.name + suffix).write_bytes(content)
        # Recovery, WAL indexing and locks affect only the disposable copy.
        with closing(sqlite3.connect(database)) as connection:
            connection.row_factory = sqlite3.Row
            if connection.execute("PRAGMA integrity_check").fetchall()[0][0] != "ok":
                raise AirlockError("effect database integrity check failed")
            rows = connection.execute(
                """SELECT r.*, (SELECT state FROM effect_events e
                   WHERE e.reservation_id = r.reservation_id ORDER BY sequence DESC LIMIT 1)
                   AS latest_event_state FROM effect_reservations r
                   ORDER BY r.created_at, r.reservation_id"""
            ).fetchall()
            owners = []
            for row in rows:
                descriptor = json.loads(row["descriptor"])
                if effect_identity(descriptor) != row["effect_id"]:
                    raise AirlockError("effect descriptor does not match its stored identity")
                header_hash = descriptor.get("semantic_key", {}).get("headers_effect_sha256")
                owners.append(
                    {
                        "reference": {
                            "profile": EFFECT_PROFILE,
                            "effect_id": row["effect_id"],
                            "reservation_id": row["reservation_id"],
                            "owner_attempt_id": row["action_id"],
                        },
                        "state": row["state"],
                        "latest_event_state": row["latest_event_state"],
                        "grant_id": row["grant_id"],
                        "descriptor_sha256": digest(descriptor),
                        "legacy_header_identity": header_hash not in (None, digest({})),
                        "live_owner": row["state"] != "NOT_EXECUTED",
                    }
                )
            return owners


def _history_problems(verification: dict, owners: list[dict]) -> list[str]:
    problems = []
    by_reservation = {o["reference"]["reservation_id"]: o for o in owners}
    effects = {o["reference"]["effect_id"] for o in owners}
    references, outcomes = {}, {}
    for item in verification["rows"]:
        if not item["verified"]:
            continue
        row = item["row"]
        if row.get("effect_id") and row["effect_id"] not in effects:
            problems.append("journal effect missing from database: " + row["effect_id"])
        proof_ref = row.get("proof", {}).get("extensions", {}).get("effect")
        final_ref = row.get("effect")
        for ref in (proof_ref, final_ref):
            if ref and "reservation_id" in ref:
                references[ref["reservation_id"]] = {
                    k: ref[k]
                    for k in ("profile", "effect_id", "reservation_id", "owner_attempt_id")
                }
        if final_ref and row.get("outcome"):
            outcomes[final_ref["reservation_id"]] = row["outcome"]
        if row.get("stage") == "reconciled":
            ref = row["reconciliation"]["payload"]["reference"]
            references[ref["reservation_id"]] = ref
            outcomes[ref["reservation_id"]] = row["outcome"]
    for reservation, ref in references.items():
        owner = by_reservation.get(reservation)
        expected = outcomes.get(reservation)
        if (
            owner is None
            or owner["reference"] != ref
            or (expected and owner["state"] != expected)
            or (expected is None and owner["state"] == "NOT_EXECUTED")
        ):
            problems.append("database missing or contradicts journal attempt: " + reservation)
    for owner in owners:
        reservation = owner["reference"]["reservation_id"]
        if owner["state"] != owner["latest_event_state"]:
            problems.append("database event/owner disagreement: " + reservation)
        if owner["live_owner"] and owner["legacy_header_identity"]:
            problems.append("legacy header-dependent live owner: " + reservation)
        # Missing journal provenance is diagnostic blocking, even if the live
        # SQLite owner still suffices to prevent redispatch at runtime.
        if reservation not in references:
            problems.append("database attempt has no retained journal reference: " + reservation)
    return problems


def recovery_inventory(root: Path, *, public_key: str | None = None, checkpoint=None) -> dict:
    """Diagnose an offline snapshot; the result is never runtime authority.

    NO_DETECTED_BLOCKER is intentionally not SAFE_TO_MIGRATE. Hashes and a
    self-consistent local pair cannot establish that lost history never existed.
    """
    result = {
        "schema": "actenon-airlock/recovery-inventory/v1",
        "status": "BLOCKED",
        "read_only": True,
        "migration_supported": False,
        "snapshot_requirement": "stop all supervisors before capture",
        "trust_anchor": "operator-supplied" if public_key else "project-local-untrusted",
        "files": {},
        "owners": [],
        "problems": [],
        "limitations": [
            "Diagnostic only; does not authorize startup, migration or release of ownership.",
            "Stable file reads do not establish an atomic snapshot of a running supervisor.",
            "Without independently retained evidence, total history loss is undetectable.",
            "A signature verifies an assertion, not the external provider state.",
        ],
    }
    try:
        path = root.absolute() / ".airlock"
        captured = _capture(path)
        result["files"] = {
            name: (
                {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                if content is not None
                else None
            )
            for name, content in captured.items()
        }
        if _capture(path) != captured:
            raise AirlockError(
                "source changed during inventory; stop all supervisors and recapture"
            )
        if captured["local/permit.sqlite3-journal"]:
            raise AirlockError("interrupted SQLite rollback journal; preserve and recover a copy")
        if public_key is None:
            public_key = json.loads(captured["public-key.json"])["key"]
        journal = captured["local/receipts.jsonl"]
        if journal is None:
            result["problems"].append("receipt journal missing; completeness cannot be inferred")
            journal = b""
        evidence = verify_offline(journal, public_key, checkpoint)
        result["evidence"] = evidence
        if not evidence["integrity"]["ok"]:
            result["problems"].append("receipt integrity failed")
        if checkpoint is not None and evidence["completeness"]["status"] != "ANCHORED":
            result["problems"].append("trusted checkpoint not satisfied")
        owners = _owners(captured)
        result["owners"] = owners
        result["problems"].extend(
            _history_problems(verify_receipt_lines(journal.splitlines(), public_key), owners)
        )
    except (
        AirlockError,
        OSError,
        sqlite3.Error,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
    ) as exc:
        result["problems"].append(str(exc))
    if not result["problems"]:
        result["status"] = "NO_DETECTED_BLOCKER"
    return result
