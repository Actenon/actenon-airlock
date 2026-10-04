"""Signed evidence must remain one durable chain across broker instances."""

import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor

import pytest

from actenon_airlock.common import AirlockError
from actenon_airlock.state import State


def row(index):
    return {
        "id": f"receipt-test-{index}",
        "decision": "DENY",
        "action": "github.repo.delete",
        "target": "acme/payments",
        "execution_occurred": False,
        "credential_released": False,
    }


def test_two_writers_do_not_reuse_a_stale_chain_head(project):
    state = project("print('ready')\n")
    other = State(state.root)
    state.receipt(row(1))
    other.receipt(row(2))
    state.receipt(row(3))
    result = state.verify_receipts()
    assert result["ok"] and result["receipts"] == 3


def test_parallel_instances_append_one_verified_chain(project):
    state = project("print('ready')\n")

    def append(index):
        return State(state.root).receipt(row(index))

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert len(list(pool.map(append, range(32)))) == 32
    result = state.verify_receipts()
    assert result["ok"] and result["receipts"] == 32


def _writer(root, number, ready, start, results):
    state = State(root)
    ready.put(True)
    if not start.wait(10):
        raise RuntimeError("start timeout")
    for index in range(8):
        state.receipt(row(f"{number}-{index}"))
    results.put(True)


def test_two_processes_append_one_verified_chain(project):
    state = project("print('ready')\n")
    ctx = mp.get_context("spawn")
    ready, start, results = ctx.Queue(), ctx.Event(), ctx.Queue()
    workers = [
        ctx.Process(target=_writer, args=(state.root, number, ready, start, results))
        for number in range(2)
    ]
    try:
        for worker in workers:
            worker.start()
        assert ready.get(timeout=10) and ready.get(timeout=10)
        start.set()
        assert results.get(timeout=10) and results.get(timeout=10)
        for worker in workers:
            worker.join(10)
            assert worker.exitcode == 0
    finally:
        start.set()
        for worker in workers:
            if worker.is_alive():
                worker.kill()
                worker.join(5)
    result = state.verify_receipts()
    assert result["ok"] and result["receipts"] == 16


def test_incomplete_previous_append_refuses_to_extend_the_journal(project):
    state = project("print('ready')\n")
    state.receipt(row(1))
    with state.receipts_path.open("ab") as stream:
        stream.write(b'{"partial":')
    before = state.receipts_path.read_bytes()
    with pytest.raises(AirlockError, match="incomplete"):
        State(state.root).receipt(row(2))
    assert state.receipts_path.read_bytes() == before


@pytest.mark.parametrize("field", ["key_id", "encoding"])
def test_signature_metadata_cannot_misidentify_a_new_signed_receipt(project, field):
    import json

    state = project("print('ready')\n")
    signed = state.receipt(row(1))
    assert signed["signer_key_id"] == signed["signature"]["key_id"]
    signed["signature"][field] = "changed"
    state.receipts_path.write_text(json.dumps(signed) + "\n")
    assert not state.verify_receipts()["ok"]
