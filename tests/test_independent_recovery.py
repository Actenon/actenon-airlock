"""Independent recovery attacks; all provider traffic stays on owned loopback."""

import json
import sqlite3

import pytest
from actenon_permit.model import GrantStatus
from test_broker import message

from actenon_airlock.broker import Broker
from actenon_airlock.common import AirlockError
from actenon_airlock.evidence import verify_offline
from actenon_airlock.manifest import discover


def attempt(state, item):
    broker = Broker(state, discover(state.root))
    try:
        return broker.handle(item)
    finally:
        broker.close()


@pytest.mark.parametrize("damage", ["signature", "delete-middle", "reorder"])
def test_invalid_journal_blocks_new_consequence(project, server, damage):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\nrequests.post("{url}/b")\n')
    assert attempt(state, message(url + "/a"))["ok"]
    lines = state.receipts_path.read_bytes().splitlines()
    if damage == "signature":
        row = json.loads(lines[-1])
        row["target"] += "-forged"
        lines[-1] = json.dumps(row).encode()
    elif damage == "delete-middle":
        lines.pop(0)
    else:
        lines.reverse()
    state.receipts_path.write_bytes(b"\n".join(lines) + b"\n")
    assert not state.verify_receipts()["ok"]
    with pytest.raises(AirlockError, match="journal"):
        attempt(state, message(url + "/b", line=3))
    assert len(calls) == 1


def test_authorized_receipt_alone_preserves_crash_window_ownership(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    assert attempt(state, message(url + "/a"))["ok"]
    # A process can die after provider dispatch, before the outcome append.
    first = state.receipts_path.read_bytes().splitlines()[0]
    state.receipts_path.write_bytes(first + b"\n")
    for suffix in ("", "-wal", "-shm"):
        (state.local / ("permit.sqlite3" + suffix)).unlink(missing_ok=True)
    with pytest.raises(AirlockError, match="effect store"):
        attempt(state, message(url + "/a"))
    assert len(calls) == 1


def test_older_non_execution_attempt_cannot_hide_missing_live_owner(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    item = message(url + "/a")
    # Preserve a genuine earlier NOT_EXECUTED attempt, then a later dispatched one.
    broker = Broker(state, discover(state.root))
    # Generate non-execution at the actual Kernel edge by revoking the grant.
    edge = broker.effect_edge.protect

    def revoked(intent, proof, execute):
        broker.store.set_status(broker.grant.id, GrantStatus.REVOKED)
        return edge(intent, proof, execute)

    broker.effect_edge.protect = revoked
    try:
        assert not broker.handle(item)["ok"]
    finally:
        broker.close()
    backup = sqlite3.connect(":memory:")
    with sqlite3.connect(state.local / "permit.sqlite3") as db:
        db.backup(backup)
    assert attempt(state, item)["ok"]
    assert len(calls) == 1
    with sqlite3.connect(state.local / "permit.sqlite3") as db:
        backup.backup(db)
    backup.close()
    with pytest.raises(AirlockError, match="effect store"):
        attempt(state, item)
    assert len(calls) == 1


def test_retry_denial_does_not_erase_unresolved_provider_truth(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    assert attempt(state, message(url + "/a"))["ok"]
    assert not attempt(state, message(url + "/a"))["ok"]
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    truth = verify_offline(state.receipts_path.read_bytes(), public)["provider_truth"]
    assert len(truth["unresolved_ambiguous"]) == 1
    assert len(calls) == 1


def test_total_local_history_loss_is_not_claimed_to_be_detectable(project, server):
    from actenon_airlock.evidence import create_checkpoint

    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    assert attempt(state, message(url + "/a"))["ok"]
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    independent_checkpoint = create_checkpoint(state)
    state.receipts_path.unlink()
    for suffix in ("", "-wal", "-shm"):
        (state.local / ("permit.sqlite3" + suffix)).unlink(missing_ok=True)
    # This is an explicit LIMITATION control, not a containment pass. The local
    # broker has no configured external history authority. Its retained key
    # proves who signed, not that a previous execution never happened.
    assert attempt(state, message(url + "/a"))["ok"]
    assert len(calls) == 2
    check = verify_offline(state.receipts_path.read_bytes(), public, independent_checkpoint)
    assert check["integrity"]["ok"]
    assert not check["ok"] and check["completeness"]["status"] == "DIVERGED"


def test_deleted_journal_does_not_release_durable_owner(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    assert attempt(state, message(url + "/a"))["ok"]
    state.receipts_path.unlink()
    assert not attempt(state, message(url + "/a"))["ok"]
    assert len(calls) == 1
