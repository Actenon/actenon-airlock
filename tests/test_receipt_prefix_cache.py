"""Exact-byte reuse must never turn filesystem metadata into signing authority."""

import json
import os

import pytest
from test_receipt_concurrency import row

from actenon_airlock import state as state_module
from actenon_airlock.common import AirlockError
from actenon_airlock.evidence import create_checkpoint, verify_offline
from actenon_airlock.state import State


def test_reuse_verifies_every_other_writer_suffix_and_offline_always_full(project, monkeypatch):
    state = project("print('ready')\n")
    state.receipt(row(0))
    counts = []
    verify = state_module._verify_receipt_suffix

    def counted(lines, public, prev):
        counts.append(len(lines))
        return verify(lines, public, prev)

    monkeypatch.setattr(state_module, "_verify_receipt_suffix", counted)
    state.receipt(row(1))
    State(state.root).receipt(row(2))
    state.receipt(row(3))
    assert counts == [1, 2, 2]  # warm, cold, interleaved writer
    assert state.verify_receipts()["ok"]
    assert counts[-1] == 4  # offline never consults the append cache


@pytest.mark.parametrize("mutation", ["prefix", "suffix", "replacement", "partial"])
def test_warmed_cache_refuses_corruption_even_with_restored_metadata(project, mutation):
    state = project("print('ready')\n")
    state.receipt(row(0))
    state.receipt(row(1))
    if mutation == "suffix":
        State(state.root).receipt(row(2))
    before = state.receipts_path.stat()
    data = state.receipts_path.read_bytes()
    if mutation == "partial":
        damaged = data + b'{"unfinished":'
    else:
        index = data.rfind(b"payments") if mutation == "suffix" else data.find(b"payments")
        damaged = data[:index] + b"paymeNts" + data[index + 8 :]
    if mutation == "replacement":
        replacement = state.local / "replacement"
        replacement.write_bytes(damaged)
        replacement.replace(state.receipts_path)
    else:
        state.receipts_path.write_bytes(damaged)
    os.utime(state.receipts_path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(AirlockError, match="invalid|incomplete"):
        state.receipt(row(2))
    assert state.receipts_path.read_bytes() == damaged


@pytest.mark.parametrize("fsync_number", [1, 2])
def test_failed_durability_does_not_install_a_verified_prefix(project, monkeypatch, fsync_number):
    state = project("print('ready')\n")
    state.receipt(row(0))
    prefix = state._verified_receipt_prefix
    fsync = os.fsync
    count = 0

    def failed(fd):
        nonlocal count
        count += 1
        if count == fsync_number:
            raise OSError("injected fsync failure")
        fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", failed)
        with pytest.raises(OSError, match="injected"):
            state.receipt(row(1))
    assert state._verified_receipt_prefix == prefix
    state.receipt(row(2))  # previously written suffix must be verified again
    assert state.verify_receipts()["receipts"] == 3
    assert state.verify_receipts()["ok"]


def test_cache_cannot_claim_completeness_after_valid_rollback(project):
    state = project("print('ready')\n")
    state.receipt(row(0))
    prefix = state.receipts_path.read_bytes()
    state.receipt(row(1))
    checkpoint = create_checkpoint(state)
    state.receipts_path.write_bytes(prefix)
    state.receipt(row(2))  # full re-verification proves only prefix integrity
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    verified = verify_offline(state.receipts_path.read_bytes(), public, checkpoint)
    assert verified["integrity"]["ok"]
    assert verified["completeness"]["status"] == "DIVERGED"
    assert not verified["ok"]


def test_own_signature_does_not_cache_unverified_observer_evidence(project):
    state = project("print('ready')\n")
    state.receipt(row(0))
    state.receipt({**row(1), "stage": "reconciled", "reconciliation": {}})
    damaged = state.receipts_path.read_bytes()
    assert not state.verify_receipts()["ok"]
    with pytest.raises(AirlockError, match="invalid"):
        state.receipt(row(2))
    assert state.receipts_path.read_bytes() == damaged


def test_different_verification_key_cannot_reuse_a_cached_prefix(project):
    from actenon_permit.ed25519_signer import generate_ed25519_keypair

    state = project("print('ready')\n")
    state.receipt(row(0))
    state.receipt(row(1))
    state._receipt_key = generate_ed25519_keypair()
    before = state.receipts_path.read_bytes()
    with pytest.raises(AirlockError, match="invalid"):
        state.receipt(row(2))
    assert state.receipts_path.read_bytes() == before
