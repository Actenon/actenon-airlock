"""Operator evidence must authenticate the exact held effect, not unblock retries by fiat."""

import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from actenon.proof.signers.base import b64url_encode
from test_broker import message

from actenon_airlock.broker import Broker
from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError, canonical
from actenon_airlock.manifest import discover
from actenon_airlock.reconciliation import (
    DOMAIN,
    apply_reconciliation,
    load_operator_key,
    prepare_reconciliation,
    reconcile_from_provider,
    sign_reconciliation,
    verify_observation,
)


@pytest.fixture
def held(project, server, tmp_path):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    key_path = tmp_path.parent / (tmp_path.name + "-operator.key")
    assert (
        main(["init", "--path", str(state.root), "--approve", "--reconciler-key", str(key_path)])
        == 0
    )
    broker = Broker(state, discover(state.root))
    result = broker.handle(message(url + "/a"))
    assert result["ok"] and len(calls) == 1
    yield state, broker, result["effect_id"], key_path, url, calls
    broker.close()


def assertion(held, outcome="NOT_EXECUTED", **kwargs):
    state, _, effect_id, key_path, _, _ = held
    return sign_reconciliation(
        prepare_reconciliation(state, effect_id),
        load_operator_key(state, key_path),
        outcome=outcome,
        evidence_hash=hashlib.sha256(b"offline provider observation").hexdigest(),
        **kwargs,
    )


def _apply_in_process(root, observation, queue):
    from pathlib import Path

    from actenon_airlock.state import State

    try:
        result = apply_reconciliation(State(Path(root)), observation)
        queue.put({"applied": result["applied"], "outcome": result["outcome"]})
    except AirlockError:
        queue.put({"applied": False})


def test_confirmed_commit_stays_reserved_and_is_a_signed_operator_attestation(held):
    state, broker, effect_id, _, url, calls = held
    signed = assertion(held, "COMMITTED")
    result = apply_reconciliation(state, signed)
    assert result["outcome"] == "COMMITTED" and result["execution_occurred"] is True
    assert result["provider_dispatched"] is False
    assert broker.store.get_effect(effect_id)[-1]["state"] == "COMMITTED"
    assert not broker.handle(message(url + "/a"))["ok"] and len(calls) == 1
    assert state.verify_receipts()["ok"]
    row = next(
        r["row"] for r in state.verify_receipts()["rows"] if r["row"].get("stage") == "reconciled"
    )
    assert row["reconciliation"] == signed
    assert row["evidence_source"] == "authorized-observer-attestation"


def test_confirmed_nonexecution_permits_fresh_attempt_but_not_old_authorization(held):
    state, broker, effect_id, _, url, calls = held
    signed = assertion(held)
    apply_reconciliation(state, signed)
    apply_reconciliation(state, signed)  # identical terminal replay refunds no additional budget
    assert broker.handle(message(url + "/a"))["ok"]
    assert len(calls) == 2
    # The old signed observation addresses the old reservation, never the new one.
    apply_reconciliation(state, signed)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"
    assert not broker.handle(message(url + "/a"))["ok"] and len(calls) == 2


@pytest.mark.parametrize(
    "field",
    [
        "outcome",
        "grant_id",
        "principal",
        "action_hash",
        "descriptor_hash",
        "expected_event_sequence",
        "approval_digest",
        "project_key_hash",
        "reference",
    ],
)
def test_mutated_observation_cannot_clear_ambiguity(held, field):
    state, broker, effect_id, _, _, calls = held
    signed = deepcopy(assertion(held))
    signed["payload"][field] = "forged"
    with pytest.raises(AirlockError):
        apply_reconciliation(state, signed)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS" and len(calls) == 1
    assert state.verify_receipts()["ok"]
    assert json.loads(state.receipts_path.read_text().splitlines()[-1])["decision"] == "DENY"


def test_agent_generated_key_and_runtime_receipt_key_are_not_reconcilers(held, tmp_path):
    state, broker, effect_id, _, _, _ = held
    attacker_path = tmp_path.parent / (tmp_path.name + "-attacker.key")
    attacker = load_operator_key(state, attacker_path, create=True)
    forged = sign_reconciliation(
        prepare_reconciliation(state, effect_id),
        attacker,
        outcome="NOT_EXECUTED",
        evidence_hash="a" * 64,
    )
    with pytest.raises(AirlockError, match="approved"):
        apply_reconciliation(state, forged)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"
    with pytest.raises(AirlockError, match="outside"):
        load_operator_key(state, state.key_path)


def test_expired_observation_and_changed_approval_fail_closed(held):
    state, broker, effect_id, _, _, _ = held
    expired = assertion(held, now=datetime.now(UTC) - timedelta(minutes=20))
    with pytest.raises(AirlockError, match="expired"):
        apply_reconciliation(state, expired)
    signed = assertion(held)
    manifest = state.approved()
    manifest["reconciliation_keys"] = {}
    state.approve(manifest)
    with pytest.raises(AirlockError):
        apply_reconciliation(state, signed)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"


def test_programmatic_provider_must_return_an_authorized_signed_observation(held):
    state, broker, effect_id, key_path, _, _ = held

    def provider(request):
        return sign_reconciliation(
            request, load_operator_key(state, key_path), outcome="COMMITTED", evidence_hash="a" * 64
        )

    assert reconcile_from_provider(state, effect_id, provider)["outcome"] == "COMMITTED"
    assert broker.store.get_effect(effect_id)[-1]["state"] == "COMMITTED"


def test_cli_inspection_and_detached_signed_apply(held, tmp_path, capsys):
    state, broker, effect_id, key_path, _, _ = held
    capsys.readouterr()
    prefix = ["reconcile", effect_id, "--path", str(state.root), "--json"]
    assert main(prefix) == 0
    assert json.loads(capsys.readouterr().out)["prior_state"] == "AMBIGUOUS"
    evidence = tmp_path / "provider-result.txt"
    evidence.write_text("private provider observation, never record this text")
    detached = tmp_path / "observation.json"
    assert (
        main(
            [
                *prefix,
                "--not-executed",
                "--operator-key",
                str(key_path),
                "--evidence",
                str(evidence),
                "--output",
                str(detached),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"
    assert main([*prefix, "--approval", str(detached)]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "NOT_EXECUTED"
    assert "private provider observation" not in state.receipts_path.read_text()


def test_reading_operator_private_key_from_inside_project_is_rejected(held, tmp_path):
    state, _, _, key_path, _, _ = held
    copied = tmp_path / "copied-key.key"
    copied.write_bytes(key_path.read_bytes())
    copied.chmod(0o600)
    with pytest.raises(AirlockError, match="outside"):
        load_operator_key(state, copied)


@pytest.mark.parametrize(
    "field",
    ["action_hash", "descriptor_hash", "grant_id", "principal", "target", "action", "reference"],
)
def test_valid_signature_cannot_authorize_a_different_original_action(held, field):
    state, broker, effect_id, key_path, _, calls = held
    signed = assertion(held)
    signed["payload"][field] = "other-action"
    signed["signature"]["value"] = b64url_encode(
        load_operator_key(state, key_path).sign(DOMAIN + canonical(signed["payload"]))
    )
    with pytest.raises(AirlockError):
        apply_reconciliation(state, signed)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS" and len(calls) == 1


def test_later_boundary_observation_invalidates_detached_review(held):
    state, broker, effect_id, _, _, _ = held
    signed = assertion(held)
    payload = signed["payload"]
    broker.store.settle_effect(
        reference=payload["reference"],
        grant_id=payload["grant_id"],
        principal=payload["principal"],
        action_hash=payload["action_hash"],
        outcome="AMBIGUOUS",
        execution_occurred=None,
        evidence_hash="c" * 64,
        observer="trusted-boundary-new-observation",
    )
    with pytest.raises(AirlockError, match="changed since review"):
        apply_reconciliation(state, signed)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"


def test_unsigned_provider_claim_and_receipt_domain_signature_are_refused(held):
    state, broker, effect_id, key_path, _, _ = held
    with pytest.raises(AirlockError):
        reconcile_from_provider(state, effect_id, lambda _: {"outcome": "NOT_EXECUTED"})
    signed = assertion(held)
    signed["signature"]["value"] = b64url_encode(
        load_operator_key(state, key_path).sign(
            b"actenon-airlock/receipt/v1\n" + canonical(signed["payload"])
        )
    )
    with pytest.raises(AirlockError):
        apply_reconciliation(state, signed)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"


def test_receipt_failure_before_settlement_never_unblocks_effect(held, monkeypatch):
    state, broker, effect_id, _, _, _ = held
    signed = assertion(held)

    def unavailable(_value):
        raise OSError("injected journal failure")

    monkeypatch.setattr(state, "receipt", unavailable)
    with pytest.raises(OSError):
        apply_reconciliation(state, signed)
    assert broker.store.get_effect(effect_id)[-1]["state"] == "AMBIGUOUS"


def test_completion_append_failure_reports_already_applied_settlement(held, monkeypatch):
    state, broker, effect_id, _, _, _ = held
    signed = assertion(held)
    append = state.receipt

    def unavailable_after_intent(value):
        if value["stage"] == "reconciled":
            raise AirlockError("injected incomplete append")
        return append(value)

    monkeypatch.setattr(state, "receipt", unavailable_after_intent)
    result = apply_reconciliation(state, signed)
    assert result["applied"] is True and "receipt_warning" in result
    assert broker.store.get_effect(effect_id)[-1]["state"] == "NOT_EXECUTED"
    assert state.verify_receipts()["rows"][-1]["row"]["stage"] == "reconciliation-requested"


def test_external_operator_key_is_not_readable_by_cooperative_agent(tmp_path):
    key_path = tmp_path.parent / (tmp_path.name + "-private-operator.key")
    (tmp_path / "main.py").write_text(
        f"import pathlib\npathlib.Path({str(key_path)!r}).read_text()\n"
    )
    assert (
        main(["init", "--path", str(tmp_path), "--approve", "--reconciler-key", str(key_path)]) == 0
    )
    assert main(["run", "--path", str(tmp_path)]) == 3
    from actenon_airlock.state import State

    state = State(tmp_path)
    assert state.verify_receipts()["ok"]
    assert state.verify_receipts()["rows"][-1]["row"]["decision"] == "DENY"


def test_provider_cannot_mutate_shared_envelope_after_signature_verification(held, monkeypatch):
    from actenon_airlock import reconciliation

    state, broker, effect_id, _, _, _ = held
    shared = assertion(held, "COMMITTED")
    authenticate = reconciliation._authenticate

    def mutate_original(trusted_state, owned):
        result = authenticate(trusted_state, owned)
        shared["payload"]["outcome"] = "NOT_EXECUTED"
        shared["payload"]["execution_occurred"] = False
        return result

    monkeypatch.setattr(reconciliation, "_authenticate", mutate_original)
    result = apply_reconciliation(state, shared)
    assert result["outcome"] == "COMMITTED"
    assert broker.store.get_effect(effect_id)[-1]["state"] == "COMMITTED"
    signed_record = next(
        r["row"]["reconciliation"]
        for r in state.verify_receipts()["rows"]
        if r["row"].get("stage") == "reconciled"
    )
    assert signed_record["payload"]["outcome"] == "COMMITTED"


def test_project_owned_receipt_key_cannot_be_registered_as_operator(tmp_path):
    from actenon_airlock.state import State

    state = State(tmp_path)
    state.initialize()
    (tmp_path / "main.py").write_text("print('hello')\n")
    assert (
        main(
            ["init", "--path", str(tmp_path), "--approve", "--reconciler-key", str(state.key_path)]
        )
        == 2
    )
    assert not (state.path / "approved.json").exists()


@pytest.mark.parametrize("operation", ["link", "symlink", "rename"])
def test_cooperative_agent_cannot_alias_external_operator_key(tmp_path, operation):
    key_path = tmp_path.parent / (tmp_path.name + "-operator.key")
    (tmp_path / "main.py").write_text(
        f"import os\nfrom pathlib import Path\nos.{operation}({str(key_path)!r}, 'alias.txt')\nPath('alias.txt').read_text()\n"
    )
    assert (
        main(["init", "--path", str(tmp_path), "--approve", "--reconciler-key", str(key_path)]) == 0
    )
    assert main(["run", "--path", str(tmp_path)]) == 3
    assert not (tmp_path / "alias.txt").exists()
    assert key_path.exists()


def test_approved_tree_copy_cannot_hardlink_private_key_instead_of_source(tmp_path):
    key_path = tmp_path.parent / (tmp_path.name + "-operator.key")
    (tmp_path / "main.py").write_text(
        "import os, shutil\nfrom pathlib import Path\n"
        f"def copy(src, dst):\n    os.link({str(key_path)!r}, dst)\n    return dst\n"
        "shutil.copytree('inputs', 'out', copy_function=copy)\n"
        "Path('out/data.txt').read_text()\n"
    )
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs/data.txt").write_text("ordinary input")
    assert (
        main(["init", "--path", str(tmp_path), "--approve", "--reconciler-key", str(key_path)]) == 0
    )
    assert main(["run", "--path", str(tmp_path)]) == 3
    assert not (tmp_path / "out/data.txt").exists()
    assert key_path.stat().st_nlink == 1
    from actenon_airlock.state import State

    rows = State(tmp_path).verify_receipts()
    assert rows["ok"]
    assert rows["rows"][-1]["row"]["decision"] == "DENY"
    assert rows["rows"][-1]["row"]["action"] == "os.link"


def test_observer_receipt_verifies_offline_after_key_rotation_and_expiry(held):
    state, _, _, _, _, _ = held
    apply_reconciliation(state, assertion(held, "COMMITTED"))
    row = state.verify_receipts()["rows"][-1]["row"]
    public = json.loads((state.path / "public-key.json").read_text())["key"]
    assert (
        verify_observation(
            row["reconciliation"],
            row["authority_approval"],
            public,
            at=datetime.fromisoformat(row["settled_at"]),
        )["outcome"]
        == "COMMITTED"
    )
    with pytest.raises(AirlockError, match="expired"):
        verify_observation(
            row["reconciliation"],
            row["authority_approval"],
            public,
            at=datetime.now(UTC) + timedelta(hours=1),
        )
    approved = state.approved()
    approved["reconciliation_keys"] = {}
    state.approve(approved)
    state.key_path.unlink()  # receipt authentication needs only the trusted public key
    assert state.verify_receipts()["ok"]


def test_valid_outer_receipt_signature_cannot_hide_invalid_observer_evidence(held):
    state, _, _, _, _, _ = held
    apply_reconciliation(state, assertion(held, "COMMITTED"))
    row = deepcopy(state.verify_receipts()["rows"][-1]["row"])
    row["reconciliation"]["payload"]["outcome"] = "NOT_EXECUTED"
    row.pop("signature")
    state.receipt(row)  # real project signature, preserving a real chain
    result = state.verify_receipts()
    assert result["ok"] is False
    assert result["rows"][-1]["problem"].startswith("observer evidence")


def test_detached_cli_works_without_runtime_secrets_or_operator_private_key(held, tmp_path):
    state, broker, effect_id, key_path, _, _ = held
    path = tmp_path / "signed-observation.json"
    path.write_text(json.dumps(assertion(held, "COMMITTED")))
    key_path.unlink()
    environment = {
        name: value for name in ("PATH", "TMPDIR", "LANG") if (value := os.environ.get(name))
    }
    environment["PYTHONNOUSERSITE"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "actenon_airlock.cli",
            "reconcile",
            effect_id,
            "--path",
            str(state.root),
            "--approval",
            str(path),
            "--json",
        ],
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["outcome"] == "COMMITTED"
    assert broker.store.get_effect(effect_id)[-1]["state"] == "COMMITTED"
    assert state.verify_receipts()["ok"]


def test_conflicting_operator_processes_cannot_clear_each_others_settlement(held):
    state, broker, effect_id, _, _, calls = held
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    observations = [assertion(held, outcome) for outcome in ("COMMITTED", "NOT_EXECUTED")]
    processes = [
        context.Process(target=_apply_in_process, args=(str(state.root), observation, queue))
        for observation in observations
    ]
    for process in processes:
        process.start()
    try:
        results = [queue.get(timeout=20) for _ in processes]
        assert sum(result["applied"] for result in results) == 1
        final = broker.store.get_effect(effect_id)[-1]["state"]
        assert final == next(result["outcome"] for result in results if result["applied"])
        assert len(calls) == 1 and state.verify_receipts()["ok"]
    finally:
        for process in processes:
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join()
            assert process.exitcode == 0
        queue.close()
