"""Offline receipt verification: integrity, completeness and provider truth, separately."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from actenon_permit.ed25519_signer import generate_ed25519_keypair, save_ed25519_keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_broker import message

from actenon_airlock.broker import Broker
from actenon_airlock.cli import main
from actenon_airlock.common import canonical
from actenon_airlock.evidence import (
    CHECKPOINT_DOMAIN,
    create_checkpoint,
    load_public_key,
    verify_offline,
)
from actenon_airlock.manifest import discover
from actenon_airlock.state import State


def _handle(state: State, *messages: dict) -> None:
    broker = Broker(state, discover(state.root))
    try:
        for item in messages:
            broker.handle(item)
    finally:
        broker.close()


@pytest.fixture
def journal(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\nrequests.post("{url}/c")\n')
    _handle(state, message(url + "/a"), message(url + "/b"), message(url + "/c", line=3))
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    return state, public, url


def _lines(state: State) -> list[bytes]:
    return state.receipts_path.read_bytes().splitlines()


def _join(lines: list[bytes]) -> bytes:
    return b"\n".join(lines) + b"\n"


def test_intact_journal_verifies_offline_with_only_a_trusted_key(journal, tmp_path):
    state, public, _ = journal
    exported = tmp_path / "receipts.jsonl"
    exported.write_bytes(state.receipts_path.read_bytes())
    checkpoint = create_checkpoint(state)
    report = verify_offline(exported.read_bytes(), public, checkpoint)
    assert report["ok"]
    assert report["integrity"]["verified"] == report["integrity"]["receipts"] >= 3
    assert report["completeness"]["status"] == "ANCHORED"
    assert report["provider_truth"]["refusals_without_effect"] >= 1


@pytest.mark.parametrize(
    ("attack", "expected"),
    [
        ("edit", "signature does not verify"),
        ("remove", "hash chain broken"),
        ("reorder", "hash chain broken"),
        ("duplicate", "hash chain broken"),
    ],
)
def test_tampered_journal_fails_integrity(journal, attack, expected):
    state, public, _ = journal
    lines = _lines(state)
    assert len(lines) >= 3
    if attack == "edit":
        row = json.loads(lines[1])
        row["target"] = "https://attacker.invalid/"
        lines[1] = canonical(row)
    elif attack == "remove":
        del lines[1]
    elif attack == "reorder":
        lines[0], lines[1] = lines[1], lines[0]
    else:
        lines.insert(2, lines[1])
    report = verify_offline(_join(lines), public)
    assert not report["integrity"]["ok"] and not report["ok"]
    assert any(expected in problem for problem in report["integrity"]["problems"])


def test_truncation_is_invisible_without_a_checkpoint_and_caught_with_one(journal):
    state, public, _ = journal
    checkpoint = create_checkpoint(state)
    truncated = _join(_lines(state)[:-1])
    unanchored = verify_offline(truncated, public)
    assert unanchored["integrity"]["ok"]  # a clean prefix still has perfect integrity
    assert unanchored["completeness"]["status"] == "UNANCHORED" and not unanchored["ok"]
    anchored = verify_offline(truncated, public, checkpoint)
    assert anchored["completeness"]["status"] == "TRUNCATED" and not anchored["ok"]


def test_rollback_to_an_older_journal_is_caught_by_the_newest_checkpoint(journal):
    state, public, url = journal
    old = state.receipts_path.read_bytes()
    old_checkpoint = create_checkpoint(state)
    _handle(state, message(url + "/a"))
    newest = create_checkpoint(state)
    assert verify_offline(old, public, newest)["completeness"]["status"] == "TRUNCATED"
    # Documented limit: an old journal with its own old checkpoint is consistent.
    assert verify_offline(old, public, old_checkpoint)["completeness"]["status"] == "ANCHORED"


def test_rewritten_history_after_a_checkpoint_diverges(journal):
    state, public, url = journal
    before_last = _join(_lines(state)[:-1])
    checkpoint = create_checkpoint(state)
    state.receipts_path.write_bytes(before_last)  # host rolls back one entry...
    _handle(state, message(url + "/b"), message(url + "/b"))  # ...and appends new history
    report = verify_offline(state.receipts_path.read_bytes(), public, checkpoint)
    assert report["integrity"]["ok"]
    assert report["completeness"]["status"] == "DIVERGED" and not report["ok"]


def test_journal_and_checkpoint_resigned_by_another_key_are_rejected(journal, tmp_path):
    state, public, _ = journal
    attacker_root = tmp_path / "attacker"
    (attacker_root / ".airlock" / "local").mkdir(parents=True)
    attacker = State(attacker_root)
    save_ed25519_keypair(generate_ed25519_keypair(), attacker.key_path)
    for line in _lines(state):
        row = json.loads(line)
        row.pop("signature")
        row.pop("prev", None)
        row.pop("signer_key_id", None)
        attacker.receipt(row)
    forged_checkpoint = create_checkpoint(attacker)
    report = verify_offline(attacker.receipts_path.read_bytes(), public, forged_checkpoint)
    assert not report["integrity"]["ok"]
    assert report["integrity"]["verified"] == 0
    assert report["completeness"]["status"] == "INVALID_CHECKPOINT"


def test_altered_or_cross_domain_checkpoints_are_invalid(journal):
    state, public, _ = journal
    checkpoint = create_checkpoint(state)
    altered = json.loads(json.dumps(checkpoint))
    altered["payload"]["journal_entries"] -= 1
    journal_bytes = state.receipts_path.read_bytes()
    assert verify_offline(journal_bytes, public, altered)["completeness"]["status"] == (
        "INVALID_CHECKPOINT"
    )
    receipt = json.loads(_lines(state)[-1])
    signature = receipt.pop("signature")
    replayed = {
        "payload": receipt,
        "signature": base64.b64encode(base64.urlsafe_b64decode(signature["value"] + "==")).decode(),
    }
    assert verify_offline(journal_bytes, public, replayed)["completeness"]["status"] == (
        "INVALID_CHECKPOINT"
    )
    # And a checkpoint-domain signature cannot pass as a receipt.
    assert CHECKPOINT_DOMAIN not in canonical(checkpoint["payload"])


def test_incomplete_final_append_fails_integrity(journal):
    state, public, _ = journal
    torn = state.receipts_path.read_bytes() + b'{"schema":"actenon-airlock/receipt/v1"'
    report = verify_offline(torn, public)
    assert not report["integrity"]["ok"]


def test_ambiguous_effect_is_reported_unresolved_not_committed(project, monkeypatch):
    url = "https://api.github.com/repos/acme/support/issues"
    monkeypatch.setenv("GITHUB_TOKEN", "offline-secret")
    state = project(f'import requests\nrequests.post("{url}")\n')

    def provider(request):
        raise httpx.ReadTimeout("response lost after the provider may have committed")

    broker = Broker(state, discover(state.root))
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(provider))
    item = message(url)
    item["headers"] = {"Authorization": "Bearer " + broker.markers["GITHUB_TOKEN"]}
    try:
        assert not broker.handle(item)["ok"]
    finally:
        broker.close()
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    truth = verify_offline(state.receipts_path.read_bytes(), public)["provider_truth"]
    assert len(truth["unresolved_ambiguous"]) == 1
    assert "COMMITTED" not in truth["runtime_claims"]
    assert "offline-secret" not in state.receipts_path.read_text()


def test_cli_exit_codes_distinguish_integrity_from_completeness(journal, tmp_path, capsys):
    state, public, _ = journal
    exported = tmp_path / "receipts.jsonl"
    exported.write_bytes(state.receipts_path.read_bytes())
    checkpoint = tmp_path / "checkpoint.json"
    assert main(["checkpoint", "--path", str(state.root), "--output", str(checkpoint)]) == 0
    base = ["verify-evidence", "--path", str(tmp_path), "--journal", str(exported)]
    assert main([*base, "--public-key", public, "--checkpoint", str(checkpoint)]) == 0
    assert main([*base, "--public-key", public]) == 2
    assert main([*base, "--public-key", public, "--integrity-only"]) == 0
    other = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    assert main([*base, "--public-key", other, "--integrity-only"]) == 2
    output = capsys.readouterr().out
    assert "COMPLETENESS ANCHORED" in output and "COMPLETENESS UNANCHORED" in output


def test_checkpoint_inside_the_project_warns(journal, capsys):
    state, _, _ = journal
    inside = state.root / "checkpoint.json"
    assert main(["checkpoint", "--path", str(state.root), "--output", str(inside)]) == 0
    assert "inside the project" in capsys.readouterr().err


def test_public_key_must_be_supplied_and_valid(tmp_path):
    with pytest.raises(Exception, match="not a base64 Ed25519 key"):
        load_public_key("not-a-key")
    bogus = tmp_path / "public-key.json"
    bogus.write_text('{"nokey": 1}')
    with pytest.raises(Exception, match="not an Airlock public key file"):
        load_public_key(str(bogus))
