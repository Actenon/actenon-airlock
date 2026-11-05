"""Only the trusted supervisor process may hold the real model credential.

Host subprocesses (git, the Docker client, scoring containers) and contained
compute are each checked by an INDEPENDENT process: a probe executable on PATH,
or a probe the real Codex agent runs inside its container. Probes compare
SHA-256 digests only; no test prints or stores the synthetic secret.
"""

import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import sys
from pathlib import Path

import httpx
import pytest
from responses_fixture import ScriptedProvider, text, tool

from actenon_airlock.protected import Docker, ProtectedBroker

ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = "sk-proj-SUPERVISORsyntheticISOLATIONkey0123456789abcd"
SIGNING = "synthetic-grant-signing-key-value-for-isolation-tests"
DUMMY = "baseline-no-standing-credential"
DIGESTS = {
    "supervisor": hashlib.sha256(SUPERVISOR.encode()).hexdigest(),
    "signing": hashlib.sha256(SIGNING.encode()).hexdigest(),
}
SENSITIVE_NAMES = ("OPENAI_API_KEY", "ACTENON_SIGNING_KEY", "ACTENON_ED25519_KEY_FILE")
IMAGE = os.environ.get("AIRLOCK_TEST_CODEX_IMAGE")


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "codex_runner_isolation", ROOT / "acceptance/codex-cli/run.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROBE = """#!{python} -I
import hashlib, json, os, sys
DIGESTS = {digests!r}
REPORT = {report!r}
NAMES = {names!r}
def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()
def hits(values):
    found = set()
    for label, expected in DIGESTS.items():
        for value in values:
            if expected in (digest(value), digest(value.split("=", 1)[-1])):
                found.add(label)
    return sorted(found)
args = sys.argv[1:]
record = {{
    "tool": os.path.basename(sys.argv[0]),
    "sub": args[:2],
    "env_hits": hits(list(os.environ.values())),
    "arg_hits": hits(args),
    "sensitive_names": sorted(n for n in NAMES if n in os.environ),
    "dummy_key_argument": "OPENAI_API_KEY={dummy}" in args,
}}
with open(REPORT, "a") as stream:
    stream.write(json.dumps(record) + "\\n")
if record["tool"] == "git":
    print("0" * 40)
elif args[:2] == ["image", "inspect"]:
    print(json.dumps([{{"Id": "sha256:" + "1" * 64, "Config": {{}}}}]))
elif "pytest" in args:
    print("1 passed in 0.01s")
"""


@pytest.fixture
def probes(tmp_path, monkeypatch):
    """Probe `docker` and `git` first on PATH; supervisor secrets in this process."""
    directory = tmp_path / "probe-bin"
    directory.mkdir()
    report = tmp_path / "probe-report.jsonl"
    for name in ("docker", "git"):
        path = directory / name
        path.write_text(
            PROBE.format(
                python=sys.executable,
                digests=DIGESTS,
                report=str(report),
                names=SENSITIVE_NAMES,
                dummy=DUMMY,
            )
        )
        path.chmod(0o700)
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("OPENAI_API_KEY", SUPERVISOR)
    monkeypatch.setenv("ACTENON_SIGNING_KEY", SIGNING)
    monkeypatch.setenv("ACTENON_ED25519_KEY_FILE", str(tmp_path / "host-only-key.json"))

    def records():
        return [json.loads(line) for line in report.read_text().splitlines()]

    return records


def assert_isolated(records, *, expect):
    assert records, "the probe never ran"
    assert {r["tool"] for r in records} >= expect
    for record in records:
        assert record["env_hits"] == [], record["sub"]
        assert record["arg_hits"] == [], record["sub"]
        assert record["sensitive_names"] == [], record["sub"]


def test_runner_identity_git_and_docker_do_not_inherit_supervisor_secrets(probes):
    runner = load_runner()
    frozen = runner.identity("synthetic-image")
    assert frozen["source_commit"] == "0" * 40  # the probe answered git
    assert_isolated(probes(), expect={"git", "docker"})


class _Gateway:
    url = "http://host.docker.internal:9/unused"


def test_baseline_docker_client_gets_only_the_dummy_credential(tmp_path, probes):
    runner = load_runner()
    project = tmp_path / "project"
    shutil.copytree(ROOT / "acceptance/v2/tasks/token-bucket/repo", project)
    with (tmp_path / "agent.log").open("w") as log:
        code, _ = runner.baseline(project, "synthetic-image", log, _Gateway())
    assert code == 0
    records = probes()
    assert_isolated(records, expect={"docker"})
    launch = next(r for r in records if r["sub"][:1] == ["run"])
    assert launch["dummy_key_argument"]  # the intended in-container dummy is preserved


def test_scoring_containers_do_not_inherit_supervisor_secrets(tmp_path, probes):
    runner = load_runner()
    work = tmp_path / "work"
    shutil.copytree(ROOT / "acceptance/v2/tasks/token-bucket/repo", work)
    runner.scoring.SCORING_IMAGE = "synthetic-image"
    runner.scoring.score(ROOT / "acceptance/v2/tasks/token-bucket", work)
    assert_isolated(probes(), expect={"docker"})


def test_protected_docker_client_environment_stays_allowlisted(probes):
    Docker().call(["version"])
    assert_isolated(probes(), expect={"docker"})


def test_supervisor_scope_exposes_the_key_only_to_broker_construction(tmp_path, monkeypatch):
    from test_responses_inference import configure, message

    from actenon_airlock import credential_preflight

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    state = configure(tmp_path)
    with credential_preflight.supervisor_scope("OPENAI_API_KEY", SUPERVISOR):
        assert os.environ["OPENAI_API_KEY"] == SUPERVISOR
        subject = ProtectedBroker(
            state, runner_discover(tmp_path), state.approved()["credential_bindings"]
        )
    assert "OPENAI_API_KEY" not in os.environ
    seen = []
    provider = ScriptedProvider([[text("ok")]])

    def transport(request):
        seen.append(request.headers.get("authorization"))
        return provider(request)

    subject.http.close()
    subject.http = httpx.Client(transport=httpx.MockTransport(transport))
    try:
        # Authorised supervisor inference still materialises the real key at the edge.
        assert subject.handle(message())["outcome"] == "COMMITTED"
        assert seen == ["Bearer " + SUPERVISOR]
    finally:
        subject.close()
    assert "OPENAI_API_KEY" not in os.environ


def test_supervisor_scope_restores_a_previous_value(monkeypatch):
    from actenon_airlock import credential_preflight

    monkeypatch.setenv("OPENAI_API_KEY", "previous-dummy")
    with credential_preflight.supervisor_scope("OPENAI_API_KEY", SUPERVISOR):
        assert os.environ["OPENAI_API_KEY"] == SUPERVISOR
    assert os.environ["OPENAI_API_KEY"] == "previous-dummy"


def runner_discover(root):
    from actenon_airlock.manifest import discover

    return discover(root)


# --- Contained compute: the real unchanged Codex agent probes its own container ---

CONTAINER_PROBE = """
import glob, hashlib, os
H = {digest!r}
def d(b):
    return hashlib.sha256(b).hexdigest()
env = any(d(v.encode()) == H for v in os.environ.values())
proc, readable = False, 0
for base in glob.glob("/proc/[0-9]*"):
    for name in ("environ", "cmdline"):
        try:
            data = open(base + "/" + name, "rb").read()
        except OSError:
            continue
        readable += 1
        for token in data.split(bytes(1)):
            if H in (d(token), d(token.split(b"=", 1)[-1])):
                proc = True
key = os.environ.get("OPENAI_API_KEY")
print("ISOLATION-PROBE", env, proc, readable, d(key.encode()) if key else "none")
"""
PROBE_COMMAND = "python -c " + shlex.quote(CONTAINER_PROBE.format(digest=DIGESTS["supervisor"]))


def probe_result(provider):
    # Match the printed result only, never the command text that also names the marker.
    pattern = re.compile(r"ISOLATION-PROBE (True|False) (True|False) (\d+) ([0-9a-f]{64}|none)")
    for request in provider.requests[1:]:
        found = pattern.search(request.content.decode())
        if found:
            env, proc, readable, key = found.groups()
            return {"env": env, "proc": proc, "readable": int(readable), "key": key}
    raise AssertionError("the contained agent never returned the probe result")


def assert_no_secret_bytes(*roots):
    for root in roots:
        for path in Path(root).rglob("*"):
            if path.is_file() and not path.is_symlink() and path.name != "key.json":
                assert SUPERVISOR.encode() not in path.read_bytes(), path


@pytest.mark.skipif(not IMAGE, reason="requires pinned Codex compute image")
def test_protected_contained_agent_never_holds_the_supervisor_key(tmp_path, monkeypatch, capfd):
    from test_codex_container import run_agent

    provider = ScriptedProvider([[tool("probe", PROBE_COMMAND)], [text("Probe complete.")]])
    import test_codex_container

    monkeypatch.setattr(test_codex_container, "SECRET", SUPERVISOR)
    assert run_agent(tmp_path, monkeypatch, provider) == 0
    result = probe_result(provider)
    assert result["env"] == "False" and result["proc"] == "False" and result["readable"] > 0
    assert result["key"] != DIGESTS["supervisor"]  # an opaque marker, never the key
    out, err = capfd.readouterr()
    assert SUPERVISOR not in out + err
    assert_no_secret_bytes(tmp_path / ".airlock/local/runs")


@pytest.mark.skipif(not IMAGE, reason="requires pinned Codex compute image")
def test_baseline_contained_agent_gets_only_the_dummy_credential(tmp_path, monkeypatch, capfd):
    from actenon_airlock.state import State

    runner = load_runner()
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    project = tmp_path / "project"
    shutil.copytree(ROOT / "acceptance/v2/tasks/token-bucket/repo", project)
    shutil.copyfile(ROOT / "acceptance/v2/tasks/token-bucket/ISSUE.md", project / "ISSUE.md")
    configure_like_runner(project, runner)
    provider = ScriptedProvider([[tool("probe", PROBE_COMMAND)], [text("Probe complete.")]])

    def fixture(request):
        reply = provider(request)
        content = reply.content.replace(b'gpt-5.5"', runner.MODEL.encode() + b'"')
        return httpx.Response(reply.status_code, headers=reply.headers, content=content)

    state = State(project)
    # The supervisor holds the key while its broker reads it (as the runner does).
    monkeypatch.setenv("OPENAI_API_KEY", SUPERVISOR)
    broker = ProtectedBroker(
        state, runner_discover(project), state.approved()["credential_bindings"]
    )
    broker.http.close()
    broker.http = httpx.Client(transport=httpx.MockTransport(fixture))
    gateway = runner.Gateway(broker)
    try:
        with (tmp_path / "agent.log").open("w") as log:
            code, work = runner.baseline(project, IMAGE, log, gateway)
    finally:
        gateway.close()
        broker.close()
    assert code == 0, (tmp_path / "agent.log").read_text()[-2000:]
    assert provider.requests[0].headers["authorization"] == "Bearer " + SUPERVISOR
    result = probe_result(provider)
    assert result["env"] == "False" and result["proc"] == "False" and result["readable"] > 0
    assert result["key"] == hashlib.sha256(DUMMY.encode()).hexdigest()  # dummy preserved
    out, err = capfd.readouterr()
    assert SUPERVISOR not in out + err
    assert_no_secret_bytes(work, tmp_path / "agent.log")


def configure_like_runner(project, runner):
    from actenon_airlock.cli import main as airlock

    common = ["--path", str(project), "--model", runner.MODEL, "--approve"]
    assert (
        airlock(
            ["setup", *common, "--agent", "codex-cli", "--max-run-usd", runner.BUDGET]
            + ["--price-per-mtok", runner.PRICES]
        )
        == 0
    )
    assert (
        airlock(
            ["init", *common, "--model-provider", "openai-responses"]
            + ["--model-contract", "openai-responses-agent/v1"]
            + ["--model-max-input-bytes", "200000", "--model-max-tokens", "16000"]
            + ["--model-price", runner.PRICES, "--model-max-run-usd", runner.BUDGET]
        )
        == 0
    )
