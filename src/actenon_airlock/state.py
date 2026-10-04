"""Local approval integrity and durable evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
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

    @property
    def receipts_path(self) -> Path:
        return self.local / "receipts.jsonl"

    def receipt(self, value: dict) -> dict:
        """Append one Ed25519-signed receipt, chained to the previous line by SHA-256."""
        self.local.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not hasattr(self, "_receipt_key"):
            self._receipt_key = load_ed25519_keypair(self.key_path)
            self._receipt_prev = _last_line_digest(self.receipts_path)
        key = self._receipt_key
        row = {**value, "schema": RECEIPT_SCHEMA, "prev": self._receipt_prev}
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
        self._receipt_prev = hashlib.sha256(line).hexdigest()
        return row

    def verify_receipts(self) -> dict:
        """Check every receipt against the project's committed public key and the hash chain."""
        try:
            public = json.loads((self.path / "public-key.json").read_text())["key"]
            verifier = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
        except (OSError, ValueError, KeyError) as exc:
            raise AirlockError("Project public key is missing or invalid") from exc
        try:
            lines = self.receipts_path.read_bytes().splitlines()
        except FileNotFoundError:
            lines = []
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
                elif row.get("prev") != prev:
                    problem = "hash chain broken (a receipt was removed, reordered, or edited)"
                else:
                    try:
                        verifier.verify(
                            b64url_decode(signature["value"]), RECEIPT_DOMAIN + canonical(unsigned)
                        )
                    except Exception:
                        problem = "signature does not verify against public-key.json"
            prev = hashlib.sha256(line).hexdigest()
            rows.append(
                {"line": number, "row": row, "verified": problem is None, "problem": problem}
            )
        return {
            "schema": "actenon-airlock/receipt-verification/v1",
            "receipts": len(rows),
            "verified": sum(r["verified"] for r in rows),
            "ok": all(r["verified"] for r in rows),
            "rows": rows,
        }


def _last_line_digest(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            end = stream.tell()
            size = min(end, 1 << 20)
            while True:
                stream.seek(end - size)
                tail = stream.read(size).rstrip(b"\n")
                if b"\n" in tail or size == end:
                    break
                size = min(end, size * 2)
    except FileNotFoundError:
        return None
    last = tail.rsplit(b"\n", 1)[-1]
    return hashlib.sha256(last).hexdigest() if last else None
