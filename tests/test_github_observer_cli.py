"""CLI uses the real observer and settlement path with fixture HTTP only."""

import json

import httpx
import pytest
from test_github_observer import Readback
from test_github_observer import held as observer_held

from actenon_airlock import github_observer
from actenon_airlock.cli import main
from actenon_airlock.reconciliation import load_operator_key, operator_identity

held = observer_held


def configured_cli(held, monkeypatch, *, fault=None):
    state, review, _, _, effect_id, _ = held
    key_path = state.root.parent / (state.root.name + "-observer.key")
    private = load_operator_key(state, key_path, create=True)
    kid, public = operator_identity(private)
    state.approve({**state.approved(), "reconciliation_keys": {kid: public}})
    provider = Readback(review, fault=fault)
    actual = github_observer.observe_github

    def observe(state, effect_id, private):
        with httpx.Client(transport=httpx.MockTransport(provider)) as client:
            return actual(state, effect_id, private, client=client)

    monkeypatch.setattr(github_observer, "observe_github", observe)
    prefix = ["reconcile", effect_id, "--path", str(state.root), "--json"]
    args = [*prefix, "--github-readback", "--operator-key", str(key_path)]
    return prefix, args, provider


def test_cli_positive_readback_applies_verified_observation_without_another_write(
    held, monkeypatch, capsys
):
    _, args, provider = configured_cli(held, monkeypatch)
    capsys.readouterr()
    assert main(args) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["applied"] and value["outcome"] == "COMMITTED"
    assert value["causal_attribution"] == "not_proven"
    assert value["provider_dispatched"] is False
    assert held[3].store.get_effect(held[4])[-1]["state"] == "COMMITTED"
    assert len(held[5].mutations) == 1
    assert all(request.method == "GET" for request in provider.calls)
    assert held[0].verify_receipts()["ok"]


def test_cli_detached_readback_keeps_ownership_held_until_signed_apply(
    held, monkeypatch, capsys, tmp_path
):
    prefix, args, _ = configured_cli(held, monkeypatch)
    capsys.readouterr()
    output = tmp_path / "detached.json"
    assert main([*args, "--output", str(output)]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["signed"] and not value["applied"]
    assert held[3].store.get_effect(held[4])[-1]["state"] == "AMBIGUOUS"
    assert main([*prefix, "--approval", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "COMMITTED"
    assert len(held[5].mutations) == 1


@pytest.mark.parametrize("fault", ["404", "timeout", "content"])
def test_cli_ambiguous_readback_never_writes_a_settlement_file(
    held, monkeypatch, capsys, tmp_path, fault
):
    _, args, _ = configured_cli(held, monkeypatch, fault=fault)
    before = held[3].store.get_effect(held[4])
    capsys.readouterr()
    output = tmp_path / "must-not-exist.json"
    assert main([*args, "--output", str(output)]) == 4
    value = json.loads(capsys.readouterr().out)
    assert value["outcome"] == "AMBIGUOUS"
    assert not value["signed"] and not value["applied"]
    assert not output.exists()
    assert held[3].store.get_effect(held[4]) == before
    assert len(held[5].mutations) == 1


def test_cli_refuses_manual_evidence_for_provider_readback(held, monkeypatch, capsys, tmp_path):
    _, args, provider = configured_cli(held, monkeypatch)
    capsys.readouterr()
    assert main([*args, "--evidence", str(tmp_path / "untrusted.json")]) == 2
    assert "obtains its own evidence" in json.loads(capsys.readouterr().out)["error"]
    assert not provider.calls
