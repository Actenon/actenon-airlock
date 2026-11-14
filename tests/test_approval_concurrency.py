"""Racing or interrupted approvals must leave one usable trust anchor."""

import base64
import json
import multiprocessing as mp
import threading
from pathlib import Path

import pytest
from actenon_permit.ed25519_signer import load_ed25519_keypair

from actenon_airlock import state as state_module
from actenon_airlock.manifest import discover
from actenon_airlock.state import State, atomic_json


def manifest_for(root):
    return dict(discover(root, env={}), command=["main.py"])


def new_project(path):
    path.mkdir()
    (path / "main.py").write_text("print('ready')\n")
    return path


def assert_usable(root):
    state = State(root)
    local = base64.b64encode(load_ed25519_keypair(state.key_path).public_key_bytes).decode()
    assert json.loads((state.path / "public-key.json").read_text())["key"] == local
    assert state.approved()["command"] == ["main.py"]
    assert json.loads((state.local / "grant-key.json").read_text())["key"]
    assert not list(state.path.rglob("*.tmp"))


def test_two_first_time_approvers_create_one_key(tmp_path, monkeypatch):
    """Both threads must not get past the "no key yet" check before either writes one."""
    root = new_project(tmp_path / "project")
    manifest = manifest_for(root)
    together = threading.Barrier(2)
    generated, errors = [], []
    real_generate = state_module.generate_ed25519_keypair

    def generate():
        generated.append(threading.get_ident())
        try:
            # Reached by both threads only when key creation is not serialised.
            together.wait(timeout=1)
        except threading.BrokenBarrierError:
            pass
        return real_generate()

    monkeypatch.setattr(state_module, "generate_ed25519_keypair", generate)

    def approve():
        try:
            State(root).approve(manifest)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=approve) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == []
    assert len(generated) == 1
    assert_usable(root)


def _approver(roots, together, failures):
    for root in roots:
        manifest = manifest_for(root)
        together.wait(60)
        try:
            State(root).approve(manifest)
        except Exception as exc:
            failures.put(f"{root.name}: {type(exc).__name__}: {exc}")


def test_racing_processes_leave_every_project_usable(tmp_path):
    racers, rounds = 4, 6
    roots = [new_project(tmp_path / f"project-{index}") for index in range(rounds)]
    ctx = mp.get_context("spawn")
    together, failures = ctx.Barrier(racers), ctx.Queue()
    workers = [
        ctx.Process(target=_approver, args=(roots, together, failures)) for _ in range(racers)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(120)
    assert [worker.exitcode for worker in workers] == [0] * racers
    assert failures.empty(), failures.get()
    for root in roots:
        assert_usable(root)


def test_reapproval_survives_an_interrupted_earlier_write(tmp_path):
    """A temporary file left by a killed process must not block later approvals."""
    root = new_project(tmp_path / "project")
    manifest = manifest_for(root)
    State(root).approve(manifest)
    for name in ("approved.json", "proposed.json", "public-key.json"):
        (root / ".airlock" / (name + ".tmp")).write_text("{")
    atomic_json(root / ".airlock" / "proposed.json", manifest)
    State(root).approve(manifest)
    assert State(root).approved()["command"] == ["main.py"]


@pytest.mark.parametrize("interrupted", ["grant-key.json", "public-key.json", "approved.json"])
def test_a_first_approval_interrupted_at_any_file_can_be_completed(
    tmp_path, monkeypatch, interrupted
):
    """Dying part-way through first-time setup must not leave a half-initialised project."""
    root = new_project(tmp_path / "project")
    manifest = manifest_for(root)
    real_atomic_json = state_module.atomic_json

    def die_at(path, *args, **kwargs):
        if path.name == interrupted:
            raise KeyboardInterrupt
        return real_atomic_json(path, *args, **kwargs)

    monkeypatch.setattr(state_module, "atomic_json", die_at)
    with pytest.raises(KeyboardInterrupt):
        State(root).approve(manifest)
    monkeypatch.undo()
    State(root).approve(manifest)
    assert_usable(root)


def test_an_interrupted_key_write_leaves_no_key_behind(tmp_path, monkeypatch):
    root = new_project(tmp_path / "project")
    manifest = manifest_for(root)
    real_replace = state_module.os.replace

    def die_before_the_key_lands(source, target):
        if Path(target).name == "key.json":
            raise KeyboardInterrupt
        return real_replace(source, target)

    monkeypatch.setattr(state_module.os, "replace", die_before_the_key_lands)
    with pytest.raises(KeyboardInterrupt):
        State(root).approve(manifest)
    monkeypatch.undo()
    assert sorted(p.name for p in State(root).local.iterdir()) == [
        "approval.lock",
        "grant-key.json",
    ]
    State(root).approve(manifest)
    assert_usable(root)
