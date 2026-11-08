"""A receipt line must be exactly the canonical bytes that were signed.

Found by the independent offline verifier (release/north-star/verifier): Airlock's own
verifier re-canonicalised the parsed row before checking the signature, so a reformatted final
line, or one carrying a duplicate member that a first-wins JSON reader would see differently,
still verified when no checkpoint anchored it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from actenon_airlock.common import canonical
from actenon_airlock.state import RECEIPT_DOMAIN, RECEIPT_SCHEMA, verify_receipt_lines

ROOT = Path(__file__).resolve().parents[1]


def journal(n: int = 3) -> tuple[list[bytes], str]:
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    lines, prev = [], None
    for i in range(n):
        row = {"action": "http.post", "decision": "DENY", "n": i, "schema": RECEIPT_SCHEMA,
               "signer_key_id": "k", "prev": prev}  # fmt: skip
        row["signature"] = {
            "algorithm": "EdDSA", "key_id": "k", "encoding": "base64url",
            "value": base64.urlsafe_b64encode(key.sign(RECEIPT_DOMAIN + canonical(row))).decode().rstrip("="),
        }  # fmt: skip
        line = canonical(row)
        lines.append(line)
        prev = hashlib.sha256(line).hexdigest()
    return lines, public


def test_canonical_lines_verify():
    lines, public = journal()
    assert verify_receipt_lines(lines, public)["ok"]


def test_a_reformatted_final_line_is_refused():
    lines, public = journal()
    lines[-1] = json.dumps(json.loads(lines[-1]), sort_keys=True).encode()  # spaces added
    result = verify_receipt_lines(lines, public)
    assert not result["ok"]
    assert (
        result["rows"][-1]["problem"]
        == "receipt line is not the exact canonical bytes that were signed"
    )


def test_a_duplicate_member_in_the_final_line_is_refused():
    lines, public = journal()
    lines[-1] = lines[-1].replace(b"{", b'{"decision":"ALLOW",', 1)
    assert json.loads(lines[-1])["decision"] == "DENY"  # last wins, so the signature still matches
    result = verify_receipt_lines(lines, public)
    assert not result["ok"] and not result["rows"][-1]["verified"]


@pytest.mark.parametrize(
    "path",
    subprocess.run(
        ["git", "ls-files", "release/**/receipts.jsonl", "docs/evidence/**/receipts.jsonl"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split(),
)  # fmt: skip
def test_every_committed_journal_still_verifies(path):
    """The stricter rule must not reject any historical evidence (frozen corpus)."""
    journal_path = ROOT / path
    key = json.loads((journal_path.parent / "public-key.json").read_text())["key"]
    result = verify_receipt_lines(journal_path.read_bytes().splitlines(), key)
    assert result["ok"], [r["problem"] for r in result["rows"] if not r["verified"]][:3]
