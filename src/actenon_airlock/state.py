"""Local approval integrity and durable evidence."""

from __future__ import annotations

import base64
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from actenon_permit.ed25519_signer import (
    generate_ed25519_keypair,
    load_ed25519_keypair,
    save_ed25519_keypair,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .manifest import AirlockError, canonical


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

    def receipt(self, value: dict) -> None:
        self.local.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.local / "receipts.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(canonical(value).decode() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
