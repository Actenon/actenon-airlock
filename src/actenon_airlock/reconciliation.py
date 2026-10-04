"""Separately authenticated operator/provider evidence for Permit's held effects.

This authenticates an observer's assertion. It does not turn that assertion into
independent knowledge of remote state, and does not execute the original action.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from actenon.proof.signers.base import b64url_decode, b64url_encode
from actenon_permit.state import SQLiteStore, StateError
from actenon_protocol.effects import validate_effect_outcome
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import AirlockError, canonical, digest

SCHEMA = "actenon-airlock/reconciliation/v1"
DOMAIN = (SCHEMA + "\n").encode()
REQUEST_FIELDS = {
    "schema",
    "project_key_hash",
    "approval_digest",
    "reference",
    "grant_id",
    "principal",
    "action_hash",
    "descriptor_hash",
    "expected_event_sequence",
    "prior_state",
    "action",
    "target",
    "source_digest",
    "manifest_digest",
    "proof_id",
}
ASSERTION_FIELDS = REQUEST_FIELDS | {
    "id",
    "signer_key_id",
    "issued_at",
    "expires_at",
    "outcome",
    "execution_occurred",
    "evidence_hash",
}


def _public(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def operator_identity(private):
    public = _public(private)
    return "operator_" + hashlib.sha256(public).hexdigest(), b64url_encode(public)


def load_operator_key(state, path: Path, *, create=False):
    """Explicit external local custody; the runtime receipt key is never an operator key."""
    path = path.expanduser().absolute()
    if path.is_symlink() or path.resolve().is_relative_to(state.root):
        raise AirlockError(
            "Operator private key must be outside the agent project, without a leaf symlink"
        )
    if path.suffix != ".key":
        raise AirlockError(
            "Operator private key filename must end in .key; cooperative workers deny private-key reads"
        )
    if create and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        private = Ed25519PrivateKey.generate()
        data = {
            "schema": SCHEMA + "/key",
            "private_key": b64url_encode(
                private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ),
        }
        # A concurrent initializer may have already created the authoritative key.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(data) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
            ):
                raise AirlockError(
                    "Operator key must be an owner-only regular file (mode 600), without hard links"
                )
            data = json.loads(stream.read(4097))
        if set(data) != {"schema", "private_key"} or data["schema"] != SCHEMA + "/key":
            raise ValueError("unsupported operator key")
        return Ed25519PrivateKey.from_private_bytes(b64url_decode(data["private_key"]))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise AirlockError("Operator key is missing or invalid") from exc


@contextmanager
def _store(state):
    path = state.local / "permit.sqlite3"
    if (
        state.path.is_symlink()
        or state.local.is_symlink()
        or path.is_symlink()
        or not path.is_file()
    ):
        raise AirlockError("No trusted local effect ledger; reconciliation cannot create one")
    store = SQLiteStore(str(path))
    try:
        yield store
    finally:
        store.close()


def prepare_reconciliation(state, effect_id, *, reference=None):
    """Read a consistent per-attempt snapshot; never release or refund authority."""
    approved = state.approved()
    with _store(state) as store:
        attempts = store.get_effect(effect_id)
    if not attempts:
        raise AirlockError("Effect was not found in this project's ledger")
    attempt = (
        next((a for a in attempts if a["reference"] == reference), None)
        if reference
        else attempts[-1]
    )
    if attempt is None:
        raise AirlockError("Reconciliation refers to another effect attempt")
    journal = state.verify_receipts()
    if not journal["ok"]:
        raise AirlockError("Receipt journal is invalid; preserve it before reconciliation")
    original = next(
        (
            item["row"]
            for item in journal["rows"]
            if item["row"].get("proof", {}).get("extensions", {}).get("effect")
            == attempt["reference"]
            and item["row"].get("grant_id") == attempt["grant_id"]
        ),
        {},
    )
    public = base64.b64decode(
        json.loads((state.path / "public-key.json").read_text())["key"], validate=True
    )
    return {
        "schema": SCHEMA,
        "project_key_hash": hashlib.sha256(public).hexdigest(),
        "approval_digest": digest(approved),
        "reference": attempt["reference"],
        "grant_id": attempt["grant_id"],
        "principal": attempt["principal"],
        "action_hash": attempt["action_hash"],
        "descriptor_hash": digest(attempt["descriptor"]),
        "expected_event_sequence": attempt["event_sequence"],
        "prior_state": attempt["state"],
        "action": original.get("action", attempt["descriptor"]["action_type"]),
        "target": original.get("target", attempt["descriptor"]["target"]["id"]),
        "source_digest": original.get("source_digest"),
        "manifest_digest": original.get("manifest_digest"),
        "proof_id": original.get("proof_id"),
    }


def sign_reconciliation(request, private, *, outcome, evidence_hash, ttl=300, now=None):
    """Provider/operator helper. The broker will independently authenticate this result."""
    if set(request) != REQUEST_FIELDS or request["schema"] != SCHEMA:
        raise AirlockError("Invalid reconciliation request")
    if outcome not in {"COMMITTED", "NOT_EXECUTED"}:
        raise AirlockError("Reconciliation must establish COMMITTED or NOT_EXECUTED")
    if type(ttl) is not int or not 0 < ttl <= 600:
        raise AirlockError("Reconciliation lifetime must be 1–600 seconds")
    occurred = outcome == "COMMITTED"
    validate_effect_outcome(outcome, occurred, evidence_hash)
    now = now or datetime.now(UTC)
    if now.utcoffset() is None:
        raise AirlockError("Reconciliation time must include a timezone")
    payload = {
        **request,
        "id": "reconciliation_" + uuid4().hex,
        "signer_key_id": operator_identity(private)[0],
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
        "outcome": outcome,
        "execution_occurred": occurred,
        "evidence_hash": evidence_hash,
    }
    return {
        "payload": payload,
        "signature": {
            "algorithm": "EdDSA",
            "key_id": payload["signer_key_id"],
            "encoding": "base64url",
            "value": b64url_encode(private.sign(DOMAIN + canonical(payload))),
        },
    }


def _authenticate_observation(envelope, approved, *, project_key_hash, at):
    """Never trust a public key or observer name provided by the agent's assertion."""
    try:
        if set(envelope) != {"payload", "signature"}:
            raise ValueError("envelope")
        payload, signature = envelope["payload"], envelope["signature"]
        if set(payload) != ASSERTION_FIELDS or payload["schema"] != SCHEMA:
            raise ValueError("payload")
        if (
            not isinstance(payload["id"], str)
            or re.fullmatch(r"reconciliation_[0-9a-f]{32}", payload["id"]) is None
        ):
            raise ValueError("observation identifier")
        if (
            set(signature) != {"algorithm", "key_id", "encoding", "value"}
            or signature["algorithm"] != "EdDSA"
            or signature["encoding"] != "base64url"
            or signature["key_id"] != payload["signer_key_id"]
        ):
            raise ValueError("signature format")
        if payload["project_key_hash"] != project_key_hash or payload["approval_digest"] != digest(
            approved
        ):
            raise ValueError("approval or project binding")
        trusted = approved.get("reconciliation_keys", {})
        public = b64url_decode(trusted[payload["signer_key_id"]])
        if payload["signer_key_id"] != "operator_" + hashlib.sha256(public).hexdigest():
            raise ValueError("key identity")
        Ed25519PublicKey.from_public_bytes(public).verify(
            b64url_decode(signature["value"]), DOMAIN + canonical(payload)
        )
        if payload["outcome"] not in {"COMMITTED", "NOT_EXECUTED"}:
            raise ValueError("outcome")
        validate_effect_outcome(
            payload["outcome"], payload["execution_occurred"], payload["evidence_hash"]
        )
        if (
            type(payload["expected_event_sequence"]) is not int
            or payload["expected_event_sequence"] <= 0
            or payload["prior_state"] not in {"RESERVED", "DISPATCHING", "AMBIGUOUS"}
        ):
            raise ValueError("review state")
        issued, expires = (datetime.fromisoformat(payload[k]) for k in ("issued_at", "expires_at"))
        now = at
        if (
            issued.utcoffset() is None
            or expires.utcoffset() is None
            or not timedelta(0) < expires - issued <= timedelta(seconds=600)
            or issued > now + timedelta(seconds=30)
        ):
            raise ValueError("time")
        if expires <= now:
            raise AirlockError("Reconciliation observation expired; obtain a fresh observation")
        return payload
    except AirlockError:
        raise
    except Exception as exc:
        raise AirlockError("Reconciliation is invalid or its signer is not approved") from exc


def verify_observation(envelope, approval_envelope, public_key, *, at):
    """Offline receipt authentication at its signed observation time.

    The public project key must be trusted independently. The approval included
    in the receipt authenticates historical observer keys, even after rotation.
    No current ledger, private key or network is needed for this verification.
    """
    from .state import verify

    approved = verify(approval_envelope, public_key)
    anchor = hashlib.sha256(base64.b64decode(public_key, validate=True)).hexdigest()
    return _authenticate_observation(envelope, approved, project_key_hash=anchor, at=at)


def _authenticate(state, envelope):
    approved = state.approved()
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    return _authenticate_observation(
        envelope,
        approved,
        project_key_hash=hashlib.sha256(base64.b64decode(public, validate=True)).hexdigest(),
        at=datetime.now(UTC),
    )


def _receipt(state, payload, *, stage, decision, **extra):
    return state.receipt(
        {
            "id": "receipt_" + uuid4().hex,
            "timestamp": datetime.now(UTC).isoformat(),
            "action": payload.get("action", "operator.reconciliation"),
            "target": payload.get("target", "<unverified>"),
            "grant_id": payload.get("grant_id"),
            "proof_id": payload.get("proof_id"),
            "source_digest": payload.get("source_digest"),
            "manifest_digest": payload.get("manifest_digest"),
            "operator_action": "reconcile",
            "stage": stage,
            "decision": decision,
            "credential_released": False,
            "provider_dispatched": False,
            "execution_occurred": None,
            **extra,
        }
    )


def apply_reconciliation(state, envelope):
    """Authenticate, bind to the original attempt, then use Permit's atomic settlement.

    A durable signed intent precedes mutation; journal failure cannot silently
    unblock an effect. If a later completion append fails, the intent and ledger
    retain the result, and retrying the identical assertion cannot refund twice.
    """
    payload = {}
    try:
        # Provider hooks may return shared mutable objects. Verify and settle
        # from this owned snapshot; no caller can alter it after verification.
        envelope = json.loads(canonical(envelope))
        payload = _authenticate(state, envelope)
        # Replays address their original reservation, even after a fresh attempt.
        original = prepare_reconciliation(
            state, payload["reference"]["effect_id"], reference=payload["reference"]
        )
        immutable = REQUEST_FIELDS - {"prior_state", "expected_event_sequence"}
        if canonical({k: payload[k] for k in immutable}) != canonical(
            {k: original[k] for k in immutable}
        ):
            raise AirlockError(
                "Reconciliation does not match the project, approval, or original action"
            )
        if original["prior_state"] not in {"COMMITTED", "NOT_EXECUTED"} and (
            original["expected_event_sequence"] != payload["expected_event_sequence"]
            or original["prior_state"] != payload["prior_state"]
        ):
            raise AirlockError("Effect changed since review; obtain a fresh observation")
        authority = json.loads((state.path / "approved.json").read_text())
        public = json.loads((state.path / "public-key.json").read_text())["key"]
        verify_observation(envelope, authority, public, at=datetime.now(UTC))
        with _store(state) as store:
            pending = _receipt(
                state,
                payload,
                stage="reconciliation-requested",
                decision="ALLOW",
                reconciliation=envelope,
                authority_approval=authority,
                effect_id=payload["reference"]["effect_id"],
            )
            settled = store.settle_effect(
                reference=payload["reference"],
                grant_id=payload["grant_id"],
                principal=payload["principal"],
                action_hash=payload["action_hash"],
                outcome=payload["outcome"],
                execution_occurred=payload["execution_occurred"],
                evidence_hash=digest(envelope),
                observer=payload["signer_key_id"],
                reconciliation=True,
                expected_event_sequence=payload["expected_event_sequence"],
                review_expires_at=datetime.fromisoformat(payload["expires_at"]),
            )
    except (AirlockError, StateError, KeyError, TypeError, ValueError) as exc:
        # Never copy unauthenticated fields or sensitive exception diagnostics.
        _receipt(
            state,
            {},
            stage="reconciliation-denied",
            decision="DENY",
            execution_occurred=False,
            reason="Reconciliation refused; effect remains unchanged",
        )
        raise AirlockError(
            str(exc) if isinstance(exc, (AirlockError, StateError)) else "Invalid reconciliation"
        ) from exc
    result = {
        "schema": SCHEMA + "/result",
        "applied": True,
        "effect_id": payload["reference"]["effect_id"],
        "outcome": settled["effect"]["outcome"],
        "execution_occurred": settled["effect"]["execution_occurred"],
        "provider_dispatched": False,
        "operator_key_id": payload["signer_key_id"],
        "receipt_id": pending["id"],
        "settled_at": settled["settled_at"],
    }
    try:
        row = _receipt(
            state,
            payload,
            stage="reconciled",
            decision="ALLOW",
            outcome=result["outcome"],
            execution_occurred=result["execution_occurred"],
            effect_id=result["effect_id"],
            reconciliation=envelope,
            authority_approval=authority,
            settled_at=result["settled_at"],
            evidence_source="authorized-observer-attestation",
            parent_receipt_id=pending["id"],
        )
        result["receipt_id"] = row["id"]
    except (OSError, AirlockError):
        result["receipt_warning"] = (
            "Settlement applied; completion append unavailable. Preserve the signed intent and ledger."
        )
    return result


def reconcile_from_provider(state, effect_id, provider):
    """Trusted parent hook; an authenticated provider returns a signed assertion.

    Never install a hook selected by agent code. Its observation goes through
    exactly the same key, binding, lifetime and atomic state checks as the CLI.
    """
    return apply_reconciliation(state, provider(prepare_reconciliation(state, effect_id)))
