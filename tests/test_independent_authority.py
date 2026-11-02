"""Actual Permit -> Kernel -> supported provider: exact request mutations."""

import base64
import copy
import json

import pytest
from test_github_protected_integration import (
    PATCH,
    ProviderFixture,
    approved_project,
    captured_broker,
    creation,
    protected_message,
    reviewed,
)


@pytest.mark.parametrize(
    "body",
    [
        b'{"branch":true,"message":"publish reviewed patch","content":"eA=="}',
        b'{"branch":1,"message":"publish reviewed patch","content":"eA=="}',
        b'{"branch":"1","message":"publish reviewed patch","content":"eA=="}',
        b'{"branch":"review","branch":"review","message":"publish reviewed patch","content":"eA=="}',
        b'{"branch":"review","message":1.0,"content":"eA=="}',
        b'{"branch":"review","message":9007199254740993,"content":"eA=="}',
        b'{"branch":"review","message":{"nested":[true,1,"1"]},"content":"eA=="}',
    ],
)
def test_typed_creation_changes_denied_before_any_provider_io(tmp_path, monkeypatch, body):
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-assurance-token")
    review = reviewed()
    state, current = approved_project(tmp_path, [review])
    provider = ProviderFixture([review])
    broker = captured_broker(state, current, provider)
    try:
        item = protected_message(review, body=base64.b64encode(body).decode())
        assert not broker.handle(item)["ok"]
        assert provider.calls == []
        assert broker.handle(protected_message(review))["ok"]
        assert len(provider.mutations) == 1
    finally:
        broker.close()


@pytest.mark.parametrize("change", ["body", "target", "capability"])
def test_mutation_after_policy_cannot_change_dispatched_request(tmp_path, monkeypatch, change):
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-assurance-token")
    review = reviewed()
    state, current = approved_project(tmp_path, [review])
    provider = ProviderFixture([review])
    broker = captured_broker(state, current, provider)
    original = broker.effect_edge.protect

    def mutate(intent, proof, execute):
        value = copy.deepcopy(intent.to_dict())
        if change == "body":
            value["action"]["parameters"]["body_sha256"] = "0" * 64
        elif change == "target":
            value["target"]["resource_id"] += "-other"
        else:
            value["action"]["capability"] += "-other"
        from actenon.models import ActionIntent

        return original(ActionIntent.from_dict(value), proof, execute)

    broker.effect_edge.protect = mutate
    try:
        assert not broker.handle(protected_message(review))["ok"]
        assert provider.calls == []
    finally:
        broker.close()


def test_order_and_json_whitespace_keep_one_reviewed_consequence(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-assurance-token")
    review = reviewed()
    state, current = approved_project(tmp_path, [review])
    provider = ProviderFixture([review])
    broker = captured_broker(state, current, provider)
    try:
        value = json.loads(creation(review))
        value = dict(reversed(list(value.items())))
        assert broker.handle(
            protected_message(
                review, body=base64.b64encode(json.dumps(value, indent=4).encode()).decode()
            )
        )["ok"]
        assert not broker.handle(protected_message(review))["ok"]
        assert len(provider.mutations) == 1
        assert (
            json.loads(provider.mutations[0].content)["content"] == base64.b64encode(PATCH).decode()
        )
    finally:
        broker.close()
