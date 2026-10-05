import httpx
import pytest
from test_model_endpoints import ENDPOINT, PROFILE, message, setup

from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.manifest import authority_diff, discover
from actenon_airlock.protected import ProtectedBroker


def configure(root, timeout):
    state = setup(root)
    state.approve(
        {**state.approved(), "protected_model": {**PROFILE, "read_timeout_seconds": timeout}}
    )
    return state


@pytest.mark.parametrize("timeout", [0, 601, True, 1.5, "600"])
def test_unbounded_or_ambiguous_model_wait_is_refused_before_dispatch(tmp_path, timeout):
    state = configure(tmp_path, timeout)
    with pytest.raises(AirlockError, match="timeout"):
        ProtectedBroker(state, discover(tmp_path, env={}))
    assert not state.receipts_path.exists()


def test_only_signed_profile_can_change_the_model_read_phase(tmp_path):
    state = configure(tmp_path, 600)
    broker = ProtectedBroker(state, discover(tmp_path, env={}))
    observed = []
    broker.http.close()
    broker.http = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: (
                observed.append(req)
                or httpx.Response(
                    200,
                    json={
                        "model": "test-model",
                        "choices": [
                            {
                                "finish_reason": "stop",
                                "message": {"role": "assistant", "content": "fixed"},
                            }
                        ],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 2},
                    },
                )
            )
        )
    )
    try:
        assert not broker.handle(message(read_timeout_seconds=60000))["ok"]
        assert not observed
        assert broker.handle(message())["ok"]
        assert observed[0].extensions["timeout"]["read"] == 600
        assert broker.http_timeout("https://ordinary.example/action") == 30
        assert state.verify_receipts()["ok"]
    finally:
        broker.close()


def test_model_timeout_still_holds_ambiguity_and_refuses_blind_retry(tmp_path):
    state = configure(tmp_path, 600)
    broker = ProtectedBroker(state, discover(tmp_path, env={}))
    observed = []

    def lost_response(req):
        observed.append(req)
        raise httpx.ReadTimeout("response lost after dispatch", request=req)

    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(lost_response))
    try:
        assert not broker.handle(message())["ok"]
        assert not broker.handle(message())["ok"]
        assert len(observed) == 1
        rows = state.verify_receipts()
        assert rows["ok"]
        unknown = next(
            row["row"] for row in rows["rows"] if row["row"].get("outcome") == "AMBIGUOUS"
        )
        assert unknown["execution_occurred"] is None
        assert broker.store.get_grant(broker.grant.id).budget.remaining == 127
    finally:
        broker.close()


def test_longer_wait_requires_review_and_shorter_wait_does_not_expand():
    before = {"powers": [], "protected_model": PROFILE}
    after = {"powers": [], "protected_model": {**PROFILE, "read_timeout_seconds": 600}}
    assert authority_diff(before, after)["runtime_status"] == "BLOCKED UNTIL APPROVED"
    assert not authority_diff(after, before)["model_constraints"]["expanded"]


def test_cli_signs_bounded_wait_and_refuses_standalone_change(tmp_path):
    state = setup(tmp_path)
    assert (
        main(
            [
                "init",
                "--path",
                str(tmp_path),
                "--approve",
                "--model",
                "test-model",
                "--model-endpoint",
                ENDPOINT,
                "--model-read-timeout",
                "600",
            ]
        )
        == 0
    )
    assert state.approved()["protected_model"]["read_timeout_seconds"] == 600
    original = (state.path / "approved.json").read_bytes()
    assert main(["init", "--path", str(tmp_path), "--approve", "--model-read-timeout", "601"]) == 2
    assert (state.path / "approved.json").read_bytes() == original
