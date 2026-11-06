"""Offline verification of Airlock receipts, with signed journal checkpoints.

Three separate questions, answered separately:

* Integrity: does every retained receipt verify against a public key the
  verifier already trusts, in an unbroken hash chain? An edited, removed,
  reordered or duplicated receipt fails here.
* Completeness: is the journal at least as long as an earlier signed
  checkpoint, and does it extend that checkpoint's head? Without a checkpoint,
  a truncated or rolled-back journal still has perfect integrity, so the
  answer is UNANCHORED rather than complete. A checkpoint only helps if it is
  stored where the agent and the host cannot rewrite it, and the newest one is
  used: an older journal with an equally old checkpoint is consistent.
* Provider truth: for each effect, what was independently observed (a
  reconciled, observer-signed settlement) versus only claimed at runtime, and
  what remains ambiguous.

The trusted key is supplied by the verifier. A key carried alongside the
journal is never used to verify it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from actenon_permit.ed25519_signer import load_ed25519_keypair
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import AirlockError, canonical
from .state import State, verify_receipt_lines

CHECKPOINT_SCHEMA = "actenon-airlock/journal-checkpoint/v1"
# Domain separation: a receipt or approval signature never verifies as a checkpoint.
CHECKPOINT_DOMAIN = b"actenon-airlock/journal-checkpoint/v1\n"


def load_public_key(value: str) -> str:
    """Accept a base64 Ed25519 key or a path to a public-key.json file."""
    candidate = Path(value)
    if candidate.is_file():
        try:
            value = json.loads(candidate.read_text())["key"]
        except (ValueError, KeyError) as exc:
            raise AirlockError(f"{candidate} is not an Airlock public key file") from exc
    try:
        raw = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise AirlockError("Trusted public key is not a base64 Ed25519 key") from exc
    return value


def create_checkpoint(state: State) -> dict:
    """Sign the current journal length and head with the project key."""
    with state._receipt_journal_lock(exclusive=False):
        try:
            lines = state.receipts_path.read_bytes().splitlines()
        except FileNotFoundError:
            lines = []
    key = load_ed25519_keypair(state.key_path)
    payload = {
        "schema": CHECKPOINT_SCHEMA,
        "journal_entries": len(lines),
        "chain_head_sha256": hashlib.sha256(lines[-1]).hexdigest() if lines else None,
        "created_at": datetime.now(UTC).isoformat(),
        "signer_key_id": key.key_id,
    }
    signature = Ed25519PrivateKey.from_private_bytes(key.private_key_bytes).sign(
        CHECKPOINT_DOMAIN + canonical(payload)
    )
    return {"payload": payload, "signature": base64.b64encode(signature).decode()}


def verify_checkpoint(envelope: dict, public_key: str) -> dict:
    try:
        payload = envelope["payload"]
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
            base64.b64decode(envelope["signature"], validate=True),
            CHECKPOINT_DOMAIN + canonical(payload),
        )
        if payload["schema"] != CHECKPOINT_SCHEMA:
            raise ValueError("schema")
        if not isinstance(payload["journal_entries"], int) or payload["journal_entries"] < 0:
            raise ValueError("journal_entries")
        return payload
    except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
        raise AirlockError("Checkpoint signature is invalid or the checkpoint was changed") from exc


def _completeness(lines: list[bytes], checkpoint: dict | None, public_key: str) -> dict:
    if checkpoint is None:
        return {
            "status": "UNANCHORED",
            "detail": "no checkpoint supplied; a truncated or rolled-back journal is undetectable",
        }
    try:
        payload = verify_checkpoint(checkpoint, public_key)
    except AirlockError as exc:
        return {"status": "INVALID_CHECKPOINT", "detail": str(exc)}
    anchored = payload["journal_entries"]
    if len(lines) < anchored:
        return {
            "status": "TRUNCATED",
            "detail": f"journal has {len(lines)} entries; the checkpoint attests {anchored}",
            "checkpoint": payload,
        }
    head = hashlib.sha256(lines[anchored - 1]).hexdigest() if anchored else None
    if head != payload["chain_head_sha256"]:
        return {
            "status": "DIVERGED",
            "detail": f"entry {anchored} differs from the checkpoint head (history rewritten)",
            "checkpoint": payload,
        }
    return {
        "status": "ANCHORED",
        "detail": f"extends a checkpoint of {anchored} entries; "
        f"{len(lines) - anchored} later entries are not yet anchored",
        "checkpoint": payload,
    }


def _provider_truth(rows: list[dict]) -> dict:
    latest: dict[str, dict] = {}
    refused = 0
    for item in rows:
        row = item["row"] if item["verified"] and isinstance(item["row"], dict) else None
        if row is None:
            continue
        if row.get("decision") == "DENY" and not row.get("effect_id"):
            refused += 1
        effect_id = row.get("effect_id")
        # A retry refusal says nothing new about the prior provider outcome.
        # Never replace its ambiguous/observed state with an outcome-less DENY.
        if effect_id and row.get("outcome"):
            latest[effect_id] = row
    observed, claimed, unresolved = {}, {}, []
    for effect_id, row in latest.items():
        outcome = row.get("outcome")
        if row.get("stage") == "reconciled":
            observed[outcome] = observed.get(outcome, 0) + 1
        elif outcome == "AMBIGUOUS":
            unresolved.append(effect_id)
        elif outcome:
            claimed[outcome] = claimed.get(outcome, 0) + 1
    return {
        "independently_observed": observed,
        "runtime_claims": claimed,
        "unresolved_ambiguous": sorted(unresolved),
        "refusals_without_effect": refused,
    }


def verify_offline(journal: bytes, public_key: str, checkpoint: dict | None = None) -> dict:
    lines = journal.splitlines()
    integrity = verify_receipt_lines(lines, public_key)
    if journal and not journal.endswith(b"\n"):
        integrity["ok"] = False
        integrity["problems"] = ["the final entry is an incomplete append"]
    completeness = _completeness(lines, checkpoint, public_key)
    ok = integrity["ok"] and completeness["status"] == "ANCHORED"
    return {
        "schema": "actenon-airlock/offline-verification/v1",
        "ok": ok,
        "integrity": {
            "ok": integrity["ok"],
            "receipts": integrity["receipts"],
            "verified": integrity["verified"],
            "chain_head_sha256": integrity["chain_head_sha256"],
            "problems": integrity.get("problems", [])
            + [f"entry {r['line']}: {r['problem']}" for r in integrity["rows"] if r["problem"]],
        },
        "completeness": completeness,
        "provider_truth": _provider_truth(integrity["rows"]),
    }
