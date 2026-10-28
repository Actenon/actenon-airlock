"""Offline integrity check only; fixture keys are not independent trusted roots."""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


results = []
for root in sorted((Path(__file__).parent / "fixture-receipts").iterdir()):
    public = json.loads((root / "public-key.json").read_text())["key"]
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
    approved = json.loads((root / "approved.json").read_text())
    key.verify(base64.b64decode(approved["signature"], validate=True), canonical(approved["payload"]))
    previous = None
    count = 0
    for line in (root / "receipts.jsonl").read_bytes().splitlines():
        row = json.loads(line)
        assert row["schema"] == "actenon-airlock/receipt/v1" and row["prev"] == previous
        signature = row.pop("signature")
        assert signature["algorithm"] == "EdDSA" and signature["encoding"] == "base64url"
        assert row["signer_key_id"] == signature["key_id"]
        encoded = signature["value"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        key.verify(raw, b"actenon-airlock/receipt/v1\n" + canonical(row))
        previous = hashlib.sha256(line).hexdigest()
        count += 1
    results.append({"fixture": root.name, "receipts": count, "signature_and_chain_integrity": True,
                    "tail_sha256": previous, "journal_completeness": "NOT_PROVEN_WITHOUT_EXTERNAL_HEAD",
                    "provider_truth": "SYNTHETIC_FIXTURE_ONLY", "independent_operator": False})
print(json.dumps(results, indent=2))
