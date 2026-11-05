"""Supervisor credential pre-flight: reject swallowed commands before any dispatch.

The V4.4 live run failed because a silent prompt consumed the runner command,
which then became the API key. The supervisor must refuse such input locally,
must never print or persist it, and may make one non-billable authentication
check that sends no prompt. Authentication success is a prerequisite only.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest


class _Lazy:
    def __getattr__(self, name):
        from actenon_airlock import credential_preflight

        return getattr(credential_preflight, name)


preflight = _Lazy()
ROOT = Path(__file__).resolve().parents[1]
GOOD = "sk-proj-" + "A1b2C3d4E5f6G7h8" * 6
SWALLOWED = (
    ".venv/bin/python acceptance/codex-cli/run.py baseline --task token-bucket --image "
    "sha256:c449dec52754bad2a55dea7bb7b1edfbf7a864475464c53edc8ad9489d9d2269 --config "
    "~/src/actenon-audit/live-codex/v44-frozen-candidate.json --out "
    "~/src/actenon-audit/live-codex/1-baseline-v4-4 --live --authorized-usd 2"
)
MODEL = "gpt-5.5-2026-04-23"
# Synthetic Anthropic-shaped values: right charset and an "sk-" prefix, so the
# generic checks alone would accept them and send them to OpenAI.
ANTHROPIC_API = "sk-ant-api03-" + "Zy9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe" * 3 + "-AbCdEfAA"
ANTHROPIC_OAUTH = "sk-ant-oat01-" + "Qw2Er3Ty4Ui5Op6As7Df8Gh9Jk0Lz" * 3 + "-XcVbNmAA"


@pytest.mark.parametrize(
    "value,reason",
    [
        (None, "missing"),
        ("", "empty"),
        (SWALLOWED, "whitespace"),
        (" " + GOOD, "whitespace"),
        (GOOD + "\n", "whitespace"),
        (GOOD[:20] + "\x00" + GOOD[20:], "control-characters"),
        (GOOD + "é", "non-ascii"),
        ("sk-short", "too-short"),
        ("sk-" + "a" * 600, "too-long"),
        ("pk-" + "a" * 60, "unexpected-prefix"),
        ("sk-" + "a" * 30 + "/bin/python", "unexpected-characters"),
        ("scripted-codex-no-real-credential", "unexpected-prefix"),
        (ANTHROPIC_API, "anthropic-key"),
        (ANTHROPIC_OAUTH, "anthropic-key"),
        ("SK-ANT-" + "a" * 40, "anthropic-key"),
    ],
)
def test_malformed_credentials_are_refused_locally(value, reason):
    assert reason in preflight.format_problems(value)


def test_a_plausible_key_passes_the_local_check():
    assert preflight.format_problems(GOOD) == []


def provider(status, body=b"{}", seen=None):
    def handle(request):
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, content=body)

    return httpx.Client(transport=httpx.MockTransport(handle))


def test_authentication_check_is_one_promptless_model_lookup():
    seen = []
    result = preflight.authenticate(GOOD, MODEL, client=provider(200, seen=seen))
    assert result == {
        "http_status": 200,
        "outcome": "authenticated",
        "meaning": preflight.MEANING,
    }
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET" and request.content == b""
    assert str(request.url) == f"https://api.openai.com/v1/models/{MODEL}"
    assert request.headers["authorization"] == "Bearer " + GOOD


@pytest.mark.parametrize(
    "status,body,outcome,code",
    [
        (
            401,
            {"error": {"code": "invalid_api_key", "message": GOOD}},
            "rejected",
            "invalid_api_key",
        ),
        (403, {"error": {"code": "unsupported_country_region_territory"}}, "rejected", None),
        (404, {"error": {"code": "model_not_found", "message": GOOD}}, "model-unavailable", None),
        (429, {"error": {"code": "insufficient_quota"}}, "unavailable", None),
        (500, b"proxy " + GOOD.encode(), "unavailable", None),
    ],
)
def test_failed_authentication_reports_fixed_vocabulary_only(status, body, outcome, code):
    content = json.dumps(body).encode() if isinstance(body, dict) else body
    result = preflight.authenticate(GOOD, MODEL, client=provider(status, content))
    assert result["http_status"] == status and result["outcome"] == outcome
    if code:
        assert result["provider_error_code"] == code
    assert GOOD not in json.dumps(result) and GOOD[-6:] not in json.dumps(result)


def test_unreachable_provider_never_reports_exception_text():
    def broken(request):
        raise httpx.ConnectError(f"cannot reach with {GOOD}")

    client = httpx.Client(transport=httpx.MockTransport(broken))
    result = preflight.authenticate(GOOD, MODEL, client=client)
    assert result == {"http_status": None, "outcome": "unreachable", "meaning": preflight.MEANING}


def test_credential_file_must_be_private_regular_and_single_line(tmp_path):
    key = tmp_path / "key"
    key.write_text(GOOD + "\n")
    key.chmod(0o600)
    assert preflight.read_credential_file(key) == GOOD
    key.chmod(0o644)
    with pytest.raises(preflight.CredentialRefused, match="readable by other users"):
        preflight.read_credential_file(key)
    key.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(key)
    with pytest.raises(preflight.CredentialRefused, match="regular file"):
        preflight.read_credential_file(link)
    key.write_text(GOOD + "\n" + GOOD + "\n")
    with pytest.raises(preflight.CredentialRefused, match="one line"):
        preflight.read_credential_file(key)


def run_live(env_key, tmp_path):
    out = tmp_path / "out"
    env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
    if env_key is not None:
        env["OPENAI_API_KEY"] = env_key
    config = tmp_path / "config.json"
    config.write_text("{}")
    command = [
        sys.executable,
        str(ROOT / "acceptance/codex-cli/run.py"),
        "baseline",
        "--image",
        "sha256:" + "0" * 64,
        "--config",
        str(config),
        "--out",
        str(out),
        "--live",
        "--authorized-usd",
        "2",
    ]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
    return result, out


@pytest.mark.parametrize("value", [SWALLOWED, "", None, "sk-short", ANTHROPIC_API])
def test_live_runner_refuses_bad_credentials_before_any_work(tmp_path, value):
    result, out = run_live(value, tmp_path)
    assert result.returncode != 0
    assert "credential" in result.stderr.lower()
    assert not out.exists()  # no evidence directory, setup, reservation or dispatch
    if value:
        assert value not in result.stdout + result.stderr
        assert "acceptance/codex-cli" not in result.stderr.split("refused", 1)[-1]


def test_anthropic_key_is_refused_before_any_request(monkeypatch):
    sent = []

    def record(request):
        sent.append(request)
        return httpx.Response(401)

    with pytest.raises(preflight.CredentialRefused, match="Anthropic") as refused:
        preflight.supervisor_credential(ANTHROPIC_API)
    assert ANTHROPIC_API not in str(refused.value) and ANTHROPIC_API[-8:] not in str(refused.value)
    assert sent == []
    # authenticate() itself also refuses, so no caller can send it to OpenAI.
    client = httpx.Client(transport=httpx.MockTransport(record))
    with pytest.raises(preflight.CredentialRefused, match="Anthropic"):
        preflight.authenticate(ANTHROPIC_API, MODEL, client=client)
    assert sent == []


@pytest.mark.parametrize(
    "value,reason",
    [
        (None, "missing"),
        ("", "empty"),
        (SWALLOWED, "whitespace"),
        (" " + ANTHROPIC_API, "whitespace"),
        (ANTHROPIC_API + "\n", "whitespace"),
        (ANTHROPIC_API[:20] + "\x00" + ANTHROPIC_API[20:], "control-characters"),
        (ANTHROPIC_API + "é", "non-ascii"),
        ("sk-short", "too-short"),
        ("sk-ant-" + "a" * 600, "too-long"),
        (GOOD, "openai-key"),
        ("sk-proj-something", "openai-key"),
        ("sk-admin-something", "openai-key"),
        (ANTHROPIC_OAUTH, "subscription-token"),
        ("pk-" + "a" * 60, "unexpected-prefix"),
        ("sk-ant-" + "a" * 30 + "/bin/python", "unexpected-characters"),
        ("scripted-anthropic-no-real-credential", "unexpected-prefix"),
    ],
)
def test_anthropic_malformed_credentials_are_refused_locally(value, reason):
    assert reason in preflight.format_problems_anthropic(value)


def test_a_plausible_anthropic_key_passes_the_local_check():
    assert preflight.format_problems_anthropic(ANTHROPIC_API) == []


def test_openai_key_is_refused_for_anthropic_before_any_request():
    sent = []

    def record(request):
        sent.append(request)
        return httpx.Response(401)

    with pytest.raises(preflight.CredentialRefused, match="OpenAI"):
        preflight.supervisor_anthropic_credential(GOOD)
    assert sent == []

    client = httpx.Client(transport=httpx.MockTransport(record))
    with pytest.raises(preflight.CredentialRefused, match="non-Anthropic"):
        preflight.authenticate_anthropic(GOOD, "claude-opus-5-5", client=client)
    assert sent == []


def test_subscription_token_is_refused_for_anthropic():
    with pytest.raises(preflight.CredentialRefused, match="subscription tokens"):
        preflight.supervisor_anthropic_credential(ANTHROPIC_OAUTH)


def test_anthropic_authentication_check_is_one_promptless_model_lookup():
    seen = []
    result = preflight.authenticate_anthropic(
        ANTHROPIC_API, "claude-opus-5-5", client=provider(200, seen=seen)
    )
    assert result == {
        "http_status": 200,
        "outcome": "authenticated",
        "meaning": preflight.MEANING,
    }
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET" and request.content == b""
    assert str(request.url) == "https://api.anthropic.com/v1/models/claude-opus-5-5"
    assert request.headers["x-api-key"] == ANTHROPIC_API
    assert request.headers["anthropic-version"] == "2023-06-01"
