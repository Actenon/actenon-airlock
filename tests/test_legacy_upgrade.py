"""Legacy ownership has no general safe hash migration. Test stopped recovery."""

import gc
import hashlib
import json
import multiprocessing
import os
import signal
import sqlite3
from pathlib import Path

import pytest
from actenon_permit.model import GrantStatus
from test_broker import message
from test_effect_durability import _wait, held_server  # noqa: F401

from actenon_airlock.broker import Broker
from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.evidence import create_checkpoint
from actenon_airlock.manifest import discover
from actenon_airlock.reconciliation import (
    apply_reconciliation,
    load_operator_key,
    prepare_reconciliation,
    sign_reconciliation,
)
from actenon_airlock.recovery import recovery_inventory
from actenon_airlock.state import State


def legacy_broker(state):
    broker = Broker(state, discover(state.root))
    broker._effect_headers = lambda headers: {"content-type": [{"literal": "application/json"}]}
    return broker


def files(state):
    # Close unreachable fixture SQLite connections before the stopped snapshot.
    gc.collect()
    return {
        str(p.relative_to(state.path)): p.read_bytes() for p in state.path.rglob("*") if p.is_file()
    }


def signed(state, key_path, effect_id, outcome):
    return sign_reconciliation(
        prepare_reconciliation(state, effect_id),
        load_operator_key(state, key_path),
        outcome=outcome,
        evidence_hash=hashlib.sha256(b"owned fixture provider observation").hexdigest(),
    )


def setup_legacy(project, server, tmp_path, *, no_dispatch=False):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    key_path = tmp_path.parent / (tmp_path.name + "-operator.key")
    assert (
        main(["init", "--path", str(state.root), "--approve", "--reconciler-key", str(key_path)])
        == 0
    )
    broker = legacy_broker(state)
    if no_dispatch == "reserved":

        def interrupted(*args):
            raise RuntimeError("injected failure before the Kernel claim")

        broker.effect_edge.protect = interrupted
    elif no_dispatch:
        protect = broker.effect_edge.protect

        def denied(intent, proof, execute):
            broker.store.set_status(broker.grant.id, GrantStatus.REVOKED)
            return protect(intent, proof, execute)

        broker.effect_edge.protect = denied
    try:
        result = broker.handle(message(url + "/a"))
        assert result["ok"] is not bool(no_dispatch)
        effect_id = next(
            r["row"]["proof"]["extensions"]["effect"]["effect_id"]
            for r in state.verify_receipts()["rows"]
            if r["row"].get("proof")
        )
    finally:
        broker.close()
    return state, key_path, effect_id, url, calls


def upgraded_child(root, item, queue):
    try:
        state = State(Path(root))
        broker = Broker(state, discover(state.root))
        try:
            queue.put(broker.handle(item))
        finally:
            broker.close()
    except AirlockError as exc:
        queue.put({"blocked": str(exc)})


def assert_fresh_process_blocked(state, item):
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    child = ctx.Process(target=upgraded_child, args=(str(state.root), item, queue))
    try:
        child.start()
        assert "legacy header-dependent" in queue.get(timeout=20)["blocked"]
        child.join(10)
        assert child.exitcode == 0
    finally:
        if child.is_alive():
            child.kill()
            child.join(10)
        queue.close()


@pytest.mark.parametrize("outcome", ["AMBIGUOUS", "COMMITTED"])
def test_readonly_inventory_and_fresh_supervisor_keep_live_legacy_ownership(
    project, server, tmp_path, outcome
):
    state, key, effect_id, url, calls = setup_legacy(project, server, tmp_path)
    if outcome == "COMMITTED":
        apply_reconciliation(state, signed(state, key, effect_id, outcome))
    changed = message(url + "/a")
    changed["headers"] = {"Content-Type": "application/json; charset=utf-8"}
    assert_fresh_process_blocked(state, changed)
    checkpoint = create_checkpoint(state)
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    # The inventory needs no signing or observer secrets, nor an existing lock.
    state.key_path.unlink()
    (state.local / "receipts.lock").unlink()
    before = files(state)
    inventory = recovery_inventory(state.root, public_key=public, checkpoint=checkpoint)
    assert files(state) == before
    assert inventory["status"] == "BLOCKED" and inventory["migration_supported"] is False
    assert inventory["evidence"]["integrity"]["ok"]
    assert inventory["evidence"]["completeness"]["status"] == "ANCHORED"
    assert inventory["owners"][0]["state"] == outcome
    assert inventory["owners"][0]["legacy_header_identity"]
    assert any("legacy header" in p for p in inventory["problems"])
    assert len(calls) == 1


def test_legacy_nonexecution_is_retained_and_allows_one_new_identity(project, server, tmp_path):
    state, _, effect_id, url, calls = setup_legacy(project, server, tmp_path, no_dispatch=True)
    assert calls == []  # real Kernel denial, not an operator claim about an executed POST
    before = state.receipts_path.read_bytes()
    inventory = recovery_inventory(state.root)
    assert inventory["status"] == "NO_DETECTED_BLOCKER"
    assert inventory["owners"][0]["state"] == "NOT_EXECUTED"
    assert inventory["owners"][0]["legacy_header_identity"]
    broker = Broker(state, discover(state.root))
    try:
        assert broker.store.get_effect(effect_id)[0]["state"] == "NOT_EXECUTED"
        item = message(url + "/a")
        item["headers"] = {"Content-Type": "application/json; charset=utf-8"}
        assert broker.handle(item)["ok"]
        assert not broker.handle(message(url + "/a"))["ok"]
    finally:
        broker.close()
    assert state.receipts_path.read_bytes().startswith(before)
    assert len(calls) == 1


def test_guard_negative_control_and_changed_approval_cannot_upgrade_live_owner(
    project, server, tmp_path, monkeypatch
):
    state, _, _, url, calls = setup_legacy(project, server, tmp_path)
    (state.root / "main.py").write_text(
        f'import requests\nrequests.post("{url}/a")\n# new revision\n'
    )
    state.approve(discover(state.root))
    with pytest.raises(AirlockError, match="legacy header-dependent"):
        Broker(State(state.root), discover(state.root))
    assert len(calls) == 1
    # Deliberately disabled guard is the negative control: the new digest is
    # different and SQLite's uniqueness alone cannot hold the old consequence.
    monkeypatch.setattr(Broker, "_require_effect_store_matches_journal", lambda self: None)
    broker = Broker(state, discover(state.root))
    try:
        item = message(url + "/a")
        item["headers"] = {"Content-Type": "application/json; charset=utf-8"}
        assert broker.handle(item)["ok"]
        assert len(calls) == 2
    finally:
        broker.close()


def legacy_child(root, item):
    broker = legacy_broker(State(Path(root)))
    try:
        broker.handle(item)
    finally:
        broker.close()


def test_killed_legacy_dispatch_and_new_process_cannot_reset_owner(project, held_server):  # noqa: F811
    url, calls, release = held_server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    release.clear()
    child = multiprocessing.get_context("spawn").Process(
        target=legacy_child, args=(str(state.root), message(url + "/a"))
    )
    try:
        child.start()
        _wait(lambda: len(calls) == 1)
        os.kill(child.pid, signal.SIGKILL)
        child.join(10)
    finally:
        release.set()
        if child.is_alive():
            child.kill()
            child.join(10)
    inventory = recovery_inventory(state.root)
    assert inventory["status"] == "BLOCKED"
    assert inventory["owners"][0]["state"] == "DISPATCHING"
    assert_fresh_process_blocked(state, message(url + "/a"))
    with pytest.raises(AirlockError, match="legacy header-dependent"):
        Broker(State(state.root), discover(state.root))
    assert len(calls) == 1


@pytest.mark.parametrize(
    "damage", ["partial", "deleted", "rollback-db", "missing-db", "inconsistent-event"]
)
def test_legacy_damaged_recovery_stays_readonly_and_blocked(project, server, tmp_path, damage):
    state, _, _, _, calls = setup_legacy(project, server, tmp_path, no_dispatch=True)
    backup = sqlite3.connect(":memory:")
    with sqlite3.connect(state.local / "permit.sqlite3") as db:
        db.backup(backup)
    broker = Broker(state, discover(state.root))
    try:
        assert broker.handle(message(server[0] + "/a"))["ok"]
    finally:
        broker.close()
    checkpoint = create_checkpoint(state)
    if damage == "partial":
        with state.receipts_path.open("ab") as stream:
            stream.write(b'{"interrupted":')
    elif damage == "deleted":
        state.receipts_path.unlink()
    elif damage == "missing-db":
        (state.local / "permit.sqlite3").unlink()
    else:
        with sqlite3.connect(state.local / "permit.sqlite3") as db:
            if damage == "rollback-db":
                backup.backup(db)
            else:
                db.execute("UPDATE effect_events SET state = 'COMMITTED'")
    backup.close()
    before = files(state)
    inventory = recovery_inventory(state.root, checkpoint=checkpoint)
    assert inventory["status"] == "BLOCKED"
    assert files(state) == before
    assert len(calls) == 1


def test_inventory_copies_wal_without_touching_source_or_including_uncommitted_changes(
    project, server, tmp_path
):
    state, _, _, _, _ = setup_legacy(project, server, tmp_path)
    db = sqlite3.connect(state.local / "permit.sqlite3")
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE inventory_wal_control (value TEXT)")
        db.commit()
        db.execute("UPDATE effect_reservations SET state = 'NOT_EXECUTED'")
        before = files(state)
        inventory = recovery_inventory(state.root)
        assert files(state) == before
        assert inventory["files"]["local/permit.sqlite3-wal"]["bytes"] > 0
        assert inventory["owners"][0]["state"] == "AMBIGUOUS"
    finally:
        db.rollback()
        db.close()


def test_missing_state_inventory_does_not_initialize_or_claim_freshness(tmp_path, capsys):
    assert main(["recovery-inventory", "--path", str(tmp_path), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "BLOCKED"
    assert not (tmp_path / ".airlock").exists()


@pytest.mark.parametrize("failure", ["intent", "completion", "partial-completion"])
def test_authenticated_legacy_recovery_survives_interrupted_settlement(
    project, server, tmp_path, monkeypatch, failure
):
    state, key, effect_id, url, calls = setup_legacy(
        project, server, tmp_path, no_dispatch="reserved"
    )
    assert calls == []  # observed no dispatch; this evidence justifies NOT_EXECUTED
    assert recovery_inventory(state.root)["owners"][0]["state"] == "RESERVED"
    with pytest.raises(AirlockError, match="legacy header-dependent"):
        Broker(state, discover(state.root))
    observation = signed(state, key, effect_id, "NOT_EXECUTED")
    original = state.receipts_path.read_bytes()
    receipt = state.receipt

    def interrupted(value):
        stage = "reconciliation-requested" if failure == "intent" else "reconciled"
        if value.get("stage") == stage:
            if failure == "partial-completion":
                with state.receipts_path.open("ab") as stream:
                    stream.write(b'{"unfinished-completion":')
            raise OSError("injected interrupted receipt write")
        return receipt(value)

    with monkeypatch.context() as patch:
        patch.setattr(state, "receipt", interrupted)
        if failure == "intent":
            with pytest.raises(OSError):
                apply_reconciliation(state, observation)
        else:
            assert "receipt_warning" in apply_reconciliation(state, observation)
    inventory = recovery_inventory(state.root)
    assert inventory["status"] == "BLOCKED"
    assert inventory["owners"][0]["state"] == (
        "RESERVED" if failure == "intent" else "NOT_EXECUTED"
    )
    assert state.receipts_path.read_bytes().startswith(original)
    with pytest.raises(AirlockError, match="legacy|journal"):
        Broker(State(state.root), discover(state.root))
    assert calls == []
    if failure == "partial-completion":
        damaged = state.receipts_path.read_bytes()
        with pytest.raises(AirlockError, match="journal"):
            apply_reconciliation(state, observation)
        assert state.receipts_path.read_bytes() == damaged
        return  # no truncating a damaged append to manufacture recovery
    # Replaying the exact, still-valid assertion completes the existing protocol.
    assert apply_reconciliation(state, observation)["applied"]
    assert recovery_inventory(state.root)["status"] == "NO_DETECTED_BLOCKER"
    broker = Broker(state, discover(state.root))
    try:
        assert broker.store.get_effect(effect_id)[0]["state"] == "NOT_EXECUTED"
        assert broker.handle(message(url + "/a"))["ok"]
        assert len(calls) == 1
    finally:
        broker.close()


def test_inventory_detects_change_during_capture_and_never_follows_symlink(project, monkeypatch):
    from actenon_airlock import recovery

    state = project("print('ready')\n")
    original = recovery._capture
    calls = 0

    def changing(path):
        nonlocal calls
        result = original(path)
        calls += 1
        if calls == 2:
            result["local/receipts.jsonl"] = b"changed"
        return result

    with monkeypatch.context() as patch:
        patch.setattr(recovery, "_capture", changing)
        assert any("source changed" in p for p in recovery_inventory(state.root)["problems"])
    state.receipts_path.symlink_to(state.key_path)
    before = files(state)
    assert recovery_inventory(state.root)["status"] == "BLOCKED"
    assert files(state) == before


@pytest.mark.parametrize("damage", ["rollback-journal", "corrupt-db", "changed-descriptor"])
def test_inventory_preserves_unrecoverable_or_substituted_database(
    project, server, tmp_path, damage
):
    state, _, _, _, calls = setup_legacy(project, server, tmp_path)
    if damage == "rollback-journal":
        (state.local / "permit.sqlite3-journal").write_bytes(b"interrupted rollback")
    elif damage == "corrupt-db":
        (state.local / "permit.sqlite3").write_bytes(b"not a database")
    else:
        with sqlite3.connect(state.local / "permit.sqlite3") as db:
            descriptor = json.loads(
                db.execute("SELECT descriptor FROM effect_reservations").fetchone()[0]
            )
            descriptor["target"]["id"] += "/changed"
            db.execute("UPDATE effect_reservations SET descriptor = ?", (json.dumps(descriptor),))
    before = files(state)
    assert recovery_inventory(state.root)["status"] == "BLOCKED"
    assert files(state) == before and len(calls) == 1
