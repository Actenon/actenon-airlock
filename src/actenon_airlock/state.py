"""Local approval integrity and durable evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from actenon.proof.signers.base import b64url_decode, b64url_encode
from actenon_permit.ed25519_signer import (
    generate_ed25519_keypair,
    load_ed25519_keypair,
    save_ed25519_keypair,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import AirlockError, canonical

RECEIPT_SCHEMA = "actenon-airlock/receipt/v1"
# Domain separation: a receipt signature can never verify as an approval signature.
RECEIPT_DOMAIN = b"actenon-airlock/receipt/v1\n"
_RECEIPT_THREAD_LOCK = threading.RLock()


def atomic_json(path: Path, data: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(data) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def verify(envelope: dict, public_key: str) -> dict:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
            base64.b64decode(envelope["signature"], validate=True), canonical(envelope["payload"])
        )
        payload = envelope["payload"]
        if payload["schema"] != "actenon-airlock/authority/v1":
            raise ValueError("unsupported schema")
        return payload
    except Exception as exc:
        raise AirlockError("Approval signature is invalid or the approval was changed") from exc


class State:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.path = self.root / ".airlock"
        self.local = self.path / "local"
        self.key_path = self.local / "key.json"

    def initialize(self) -> None:
        if self.path.is_symlink() or self.local.is_symlink():
            raise AirlockError("Airlock state may not be a symlink")
        self.local.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.local, 0o700)
        if not self.key_path.exists():
            save_ed25519_keypair(generate_ed25519_keypair(), self.key_path)
            atomic_json(self.local / "grant-key.json", {"key": os.urandom(32).hex()})
        key = load_ed25519_keypair(self.key_path)
        public = base64.b64encode(key.public_key_bytes).decode()
        public_path = self.path / "public-key.json"
        if public_path.exists() and json.loads(public_path.read_text())["key"] != public:
            raise AirlockError("Project public key does not match the local approval key")
        if not public_path.exists():
            atomic_json(public_path, {"key": public}, 0o644)
        ignore = self.path / ".gitignore"
        if not ignore.exists():
            ignore.write_text("local/\nproposed.json\n")

    def approve(self, manifest: dict) -> None:
        self.initialize()
        key = load_ed25519_keypair(self.key_path)
        payload = dict(manifest, approved_at=datetime.now(UTC).isoformat())
        signature = Ed25519PrivateKey.from_private_bytes(key.private_key_bytes).sign(
            canonical(payload)
        )
        atomic_json(
            self.path / "approved.json",
            {
                "payload": payload,
                "signature": base64.b64encode(signature).decode(),
            },
            0o644,
        )

    def approved(self) -> dict:
        try:
            key = load_ed25519_keypair(self.key_path)
            public = base64.b64encode(key.public_key_bytes).decode()
            if json.loads((self.path / "public-key.json").read_text())["key"] != public:
                raise AirlockError("Approval trust anchor changed")
            return verify(json.loads((self.path / "approved.json").read_text()), public)
        except OSError as exc:
            raise AirlockError(
                "No local approval; run airlock init --approve after review"
            ) from exc

    def from_git(self, ref: str) -> dict:
        # Fixed argument vector, no shell, and no code from the reviewed revision is executed.
        def read(name):
            result = subprocess.run(
                ["git", "-C", str(self.root), "show", f"{ref}:.airlock/{name}"],
                capture_output=True,
                check=False,
                text=True,
            )
            if result.returncode:
                raise AirlockError(f"Trusted base {ref} has no Airlock baseline ({name})")
            return json.loads(result.stdout)

        return verify(read("approved.json"), read("public-key.json")["key"])

    def checked_in_approval(self) -> dict:
        """Verify public checkout data for CI comparison, without private keys.

        The trusted base remains the comparison authority. A self-signed PR
        manifest cannot approve additions to its model or source-derived powers.
        """
        return verify(
            json.loads((self.path / "approved.json").read_text()),
            json.loads((self.path / "public-key.json").read_text())["key"],
        )

    @property
    def receipts_path(self) -> Path:
        return self.local / "receipts.jsonl"

    @contextmanager
    def _receipt_journal_lock(self, *, exclusive: bool):
        """Thread and process lock for the supported POSIX local runtime."""
        if os.name != "posix":
            raise AirlockError("The local receipt journal currently requires Linux or macOS")
        import fcntl

        self.local.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _RECEIPT_THREAD_LOCK:
            flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            fd = os.open(self.local / "receipts.lock", flags, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                yield
            finally:
                os.close(fd)  # releasing the lock also works after process death

    def receipt(self, value: dict) -> dict:
        """Append one signed receipt using the current durable journal head.

        Key caching is safe; chain-head caching is not. Both signing and append
        occur under one process-shared lock, with fsync before release. An
        interrupted partial write is preserved and blocks further append.
        """
        with self._receipt_journal_lock(exclusive=True):
            if not hasattr(self, "_receipt_key"):
                self._receipt_key = load_ed25519_keypair(self.key_path)
            key = self._receipt_key
            try:
                journal = self.receipts_path.read_bytes()
            except FileNotFoundError:
                journal = b""
            if journal and not journal.endswith(b"\n"):
                raise AirlockError("Receipt journal has an incomplete append; refusing to append")
            verified = verify_receipt_lines(
                journal.splitlines(), base64.b64encode(key.public_key_bytes).decode()
            )
            if not verified["ok"]:
                raise AirlockError("Receipt journal is invalid; refusing to append")
            row = {
                **value,
                "schema": RECEIPT_SCHEMA,
                "signer_key_id": key.key_id,
                "prev": _last_line_digest(self.receipts_path),
            }
            signature = Ed25519PrivateKey.from_private_bytes(key.private_key_bytes).sign(
                RECEIPT_DOMAIN + canonical(row)
            )
            row["signature"] = {
                "algorithm": "EdDSA",
                "key_id": key.key_id,
                "encoding": "base64url",
                "value": b64url_encode(signature),
            }
            line = canonical(row)
            with self.receipts_path.open("ab") as stream:
                stream.write(line + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            directory_fd = os.open(self.local, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return row

    def verify_receipts(self) -> dict:
        """Check every receipt against the project's committed public key and the hash chain."""
        try:
            public = json.loads((self.path / "public-key.json").read_text())["key"]
            Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
        except (OSError, ValueError, KeyError) as exc:
            raise AirlockError("Project public key is missing or invalid") from exc
        with self._receipt_journal_lock(exclusive=False):
            try:
                journal = self.receipts_path.read_bytes()
            except FileNotFoundError:
                journal = b""
        result = verify_receipt_lines(journal.splitlines(), public)
        if journal and not journal.endswith(b"\n"):
            result["ok"] = False
            result["problems"] = ["the final entry is an incomplete append"]
        return result

    def verify_ledger(self) -> dict:
        """Verify the tamper-evident, hash-chained cryptographic ledger of Receipts and Refusals."""
        return self.verify_receipts()


def verify_receipt_lines(lines: list[bytes], public: str) -> dict:
    """Verify signed, hash-chained receipt lines against a trusted public key.

    Pure: no project state, lock or file access, so the same check runs on a
    live project and on an exported journal offline.
    """
    verifier = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
    rows, prev = [], None
    for number, line in enumerate(lines, 1):
        problem, row = None, {}
        try:
            row = json.loads(line)
            signature = row["signature"]
            if not isinstance(signature, dict):
                raise TypeError("signature")
        except (ValueError, KeyError, TypeError):
            problem = "unreadable or unsigned receipt"
        if problem is None:
            unsigned = {k: v for k, v in row.items() if k != "signature"}
            if row.get("schema") != RECEIPT_SCHEMA or signature.get("algorithm") != "EdDSA":
                problem = "unsupported receipt schema or algorithm"
            elif signature.get("encoding") != "base64url":
                problem = "unsupported receipt signature encoding"
            elif "signer_key_id" in row and row["signer_key_id"] != signature.get("key_id"):
                problem = "signature key identifier differs from the signed receipt"
            elif row.get("prev") != prev:
                problem = "hash chain broken (a receipt was removed, reordered, or edited)"
            else:
                try:
                    checking_observer = False
                    verifier.verify(
                        b64url_decode(signature["value"]), RECEIPT_DOMAIN + canonical(unsigned)
                    )
                    if row.get("stage") in {"reconciliation-requested", "reconciled"}:
                        checking_observer = True
                        from .reconciliation import verify_observation

                        observation = verify_observation(
                            row["reconciliation"],
                            row["authority_approval"],
                            public,
                            at=datetime.fromisoformat(
                                row["settled_at"]
                                if row["stage"] == "reconciled"
                                else row["timestamp"]
                            ),
                        )
                        if (
                            any(
                                row.get(name) != observation[name]
                                for name in (
                                    "action",
                                    "target",
                                    "grant_id",
                                    "proof_id",
                                    "source_digest",
                                    "manifest_digest",
                                )
                            )
                            or row.get("effect_id") != observation["reference"]["effect_id"]
                        ):
                            raise ValueError(
                                "reconciliation receipt differs from its signed observation"
                            )
                        if row["stage"] == "reconciled" and (
                            row.get("outcome") != observation["outcome"]
                            or row.get("execution_occurred")
                            is not observation["execution_occurred"]
                        ):
                            raise ValueError("reconciliation receipt contradicts its observation")
                except Exception:
                    problem = (
                        "observer evidence does not verify against public-key.json"
                        if checking_observer
                        else "signature does not verify against public-key.json"
                    )
        prev = hashlib.sha256(line).hexdigest()
        rows.append({"line": number, "row": row, "verified": problem is None, "problem": problem})
    return {
        "schema": "actenon-airlock/receipt-verification/v1",
        "receipts": len(rows),
        "verified": sum(r["verified"] for r in rows),
        "ok": all(r["verified"] for r in rows),
        "chain_head_sha256": prev,
        "completeness": "prefix_integrity_only_without_external_anchor",
        "rows": rows,
    }


def verify_ledger(root_or_state: Path | str | State) -> dict:
    """Verify the tamper-evident, hash-chained ledger of Receipts and Refusals for a project."""
    state = root_or_state if isinstance(root_or_state, State) else State(Path(root_or_state))
    return state.verify_receipts()


def export_compliance_bundle(
    root_or_state: Path | str | State,
    output_path: Path | str | None = None,
    *,
    expected_head_sha256: str | None = None,
) -> dict:
    """Export an audit/compliance evidence bundle from a single locked journal snapshot.

    Note: Without an external ``expected_head_sha256`` checkpoint, hash-chain
    verification establishes prefix integrity of present rows, not completeness
    against tail truncation or whole-journal deletion.
    """
    state = root_or_state if isinstance(root_or_state, State) else State(Path(root_or_state))
    verification = state.verify_receipts()
    public_key = json.loads((state.path / "public-key.json").read_text())["key"]
    try:
        approved_manifest = state.checked_in_approval()
        approval_verified = True
        approval_error: str | None = None
    except Exception as exc:
        approved_manifest = None
        approval_verified = False
        approval_error = str(exc)

    chain_head = verification["chain_head_sha256"]
    if expected_head_sha256 is not None:
        anchor_ok = chain_head == expected_head_sha256
        completeness = "anchored" if anchor_ok else "truncated_or_mismatched"
    else:
        anchor_ok = True
        completeness = "unknown_without_external_checkpoint"

    ledger_ok = bool(
        verification["ok"] and verification["receipts"] > 0 and approval_verified and anchor_ok
    )
    allow_count = sum(
        1
        for r in verification["rows"]
        if isinstance(r["row"], dict) and r["row"].get("decision") == "ALLOW"
    )
    deny_count = sum(
        1
        for r in verification["rows"]
        if isinstance(r["row"], dict) and r["row"].get("decision") == "DENY"
    )
    bundle = {
        "schema": "actenon-airlock/compliance-bundle/v1",
        "ok": ledger_ok,
        "public_key": public_key,
        "approval_verified": approval_verified,
        "approval_error": approval_error,
        "approved_manifest": approved_manifest,
        "ledger": {
            "ok": ledger_ok,
            "prefix_integrity_ok": verification["ok"],
            "completeness": completeness,
            "total_entries": verification["receipts"],
            "verified_entries": verification["verified"],
            "allow_receipts": allow_count,
            "deny_refusals": deny_count,
            "chain_head_sha256": chain_head,
            "rows": verification["rows"],
        },
        "controls": {
            "mapping_status": "draft_unvalidated_control_mapping",
            "soc2": ["CC6.1", "CC6.6", "CC7.2"],
            "iso_42001": ["A.6.2.6", "A.8.4", "A.9.3"],
            "cyber_insurance": [
                "BOUNDED_AUTONOMY_PROOF",
                "SERVER_SIDE_SECRET_BROKERAGE",
                "TAMPER_EVIDENT_HASH_CHAIN",
            ],
        },
    }
    if output_path is not None:
        atomic_json(Path(output_path), bundle, 0o644)
    return bundle


def _last_line_digest(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            end = stream.tell()
            size = min(end, 1 << 20)
            while True:
                stream.seek(end - size)
                raw_tail = stream.read(size)
                if raw_tail and not raw_tail.endswith(b"\n"):
                    raise AirlockError(
                        "Receipt journal has an incomplete append; preserve it for recovery"
                    )
                tail = raw_tail.rstrip(b"\n")
                if b"\n" in tail or size == end:
                    break
                size = min(end, size * 2)
    except FileNotFoundError:
        return None
    last = tail.rsplit(b"\n", 1)[-1]
    return hashlib.sha256(last).hexdigest() if last else None
