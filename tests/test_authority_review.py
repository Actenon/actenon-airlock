"""Discovery is not approval: a protected agent project signs only what its boundary uses."""

import json
from pathlib import Path

from actenon_airlock.broker import Broker
from actenon_airlock.cli import main
from actenon_airlock.manifest import capability, discover
from actenon_airlock.protect import _approved
from actenon_airlock.state import State

MODEL = "claude-test-model"
PRICES = "2,2.5,0.2,10"
SETUP = [
    "--agent",
    "claude-code",
    "--model",
    MODEL,
    "--max-run-usd",
    "1",
    "--price-per-mtok",
    PRICES,
]

HOST_POWERS = """import subprocess


def open_docs():
    subprocess.run(["xdg-open", "https://example.com/docs"])


def discard(text):
    with open("/dev/null", "w") as sink:
        sink.write(text)
"""


def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "tool.py").write_text(HOST_POWERS)
    return root


def signed(root: Path) -> list[str]:
    return sorted(f"{p['action']} {p['resource']}" for p in State(root).approved()["powers"])


def test_agent_setup_signs_only_the_model_route(tmp_path, capsys):
    root = project(tmp_path)
    discovered = {f"{p['action']} {p['resource']}" for p in discover(root)["powers"]}
    assert {"process.exec xdg-open", "filesystem.write /dev/null"} <= discovered
    assert main(["setup", "--path", str(root), *SETUP, "--approve"]) == 0
    out = capsys.readouterr().out
    assert signed(root) == ["http.post api.anthropic.com/v1/messages"]
    assert "Found in this project's code but NOT granted (2)" in out
    assert "Run the program `xdg-open` on this machine  (tool.py:5)" in out
    assert "Approved and signed: 1 grant(s). Nothing else." in out
    withheld = {f"{p['action']} {p['resource']}" for p in State(root).approved()["not_granted"]}
    assert withheld == {"process.exec xdg-open", "filesystem.write /dev/null"}


def test_the_broker_never_allows_a_withheld_power(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["setup", "--path", str(root), *SETUP, "--approve"]) == 0
    current = discover(root)
    broker = Broker(State(root), current)
    for p in current["powers"]:
        allowed = capability(p) in broker.allowed
        assert allowed == (p["action"] == "http.post"), p


def test_granting_discovered_powers_needs_the_explicit_flag(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["setup", "--path", str(root), *SETUP, "--approve"]) == 0
    assert "process.exec xdg-open" not in signed(root)
    # A bare re-approval (as the guided path does) still grants nothing extra.
    assert main(["init", "--path", str(root), "--approve"]) == 0
    assert "process.exec xdg-open" not in signed(root)
    assert main(["init", "--path", str(root), "--approve", "--grant-discovered"]) == 0
    assert "process.exec xdg-open" in signed(root)


def test_a_project_without_an_agent_keeps_the_full_review(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["init", "--path", str(root), "--approve"]) == 0
    out = capsys.readouterr().out
    assert "AIRLOCK AUTHORITY DIFF" in out
    assert "process.exec xdg-open" in signed(root)


def test_a_declined_proposal_is_never_mistaken_for_an_approval(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["setup", "--path", str(root), *SETUP, "--approve"]) == 0
    wanted = {"agent": "claude-code", "model": MODEL,
              "model_endpoint": "https://api.anthropic.com/v1/messages",
              "max_run_usd": "1", "price_per_mtok": PRICES}  # fmt: skip
    assert _approved(State(root), wanted)
    # Propose a larger limit but do not approve: agent.json now records the proposal.
    raised = [*SETUP[:-4], "--max-run-usd", "5", "--price-per-mtok", PRICES]
    assert main(["setup", "--path", str(root), *raised]) == 0
    assert json.loads((root / ".airlock/agent.json").read_text())["max_run_usd"] == "5"
    assert not _approved(State(root), {**wanted, "max_run_usd": "5"})
    assert State(root).approved()["protected_model"]["max_run_microusd"] == 1_000_000


def test_new_host_code_after_approval_never_expands_what_is_signed(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["setup", "--path", str(root), *SETUP, "--approve"]) == 0
    before = signed(root)
    # The agent (or anyone) adds code that wants more: a network write and a process.
    (root / "more.py").write_text(
        "import subprocess, requests\n\n"
        "def push():\n"
        '    requests.post("https://api.github.com/repos/o/r/issues", json={})\n'
        '    subprocess.run(["curl", "https://evil.example"])\n'
    )
    assert main(["setup", "--path", str(root), *SETUP, "--approve"]) == 0
    assert main(["init", "--path", str(root), "--approve"]) == 0
    assert signed(root) == before == ["http.post api.anthropic.com/v1/messages"]
    withheld = {f"{p['action']} {p['resource']}" for p in State(root).approved()["not_granted"]}
    assert "github.issue.create github.com/o/r" in withheld
    assert "process.exec curl" in withheld


def test_the_protected_boundary_scopes_only_the_model_route(tmp_path, capsys, monkeypatch):
    from actenon_airlock.protected import ProtectedBroker

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-" + "x" * 80)
    root = project(tmp_path)
    assert main(["setup", "--path", str(root), *SETUP, "--approve"]) == 0
    state = State(root)
    broker = ProtectedBroker(state, discover(root), state.approved()["credential_bindings"])
    try:
        scopes = broker.grant_scopes()
        model = [p for p in discover(root)["powers"] if p["action"] == "http.post"]
        assert scopes.allow == [capability(model[0])] and len(model) == 1
        assert broker.allowed == {capability(model[0])}
        # Anything other than the model route or a reviewed GitHub create is refused.
        reply = broker.handle({"kind": "protected-http", "method": "POST",
                               "url": "https://api.github.com/repos/o/r/issues",
                               "headers": {}, "body": ""})  # fmt: skip
        assert not reply.get("ok") and "No reviewed protected consequence" in reply["reason"]
        reply = broker.handle({"kind": "process", "argv": ["xdg-open", "x"]})
        assert not reply.get("ok") and "No protected executor" in reply["reason"]
    finally:
        broker.close()


def test_declining_in_protect_signs_nothing(tmp_path, capsys, monkeypatch):
    import actenon_airlock.protect as protect_module

    root = project(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-" + "x" * 80)
    monkeypatch.setattr(protect_module, "ensure_image", lambda *args: None)
    monkeypatch.setattr(protect_module, "_ask", lambda: False)
    launched = []
    monkeypatch.setattr("actenon_airlock.protected.launch_protected",
                        lambda *a, **k: launched.append(a) or 0)  # fmt: skip
    code = main(["protect", "--path", str(root), "--agent", "claude-code", "Fix it"])
    out = capsys.readouterr().out
    assert code == 2 and "Nothing was approved and nothing ran" in out
    # The review shown before the question names what was found and not granted.
    assert "Found in this project's code but NOT granted (2)" in out
    assert not (root / ".airlock" / "approved.json").exists() and not launched


def test_only_reviewed_signs_nothing_discovered_in_any_project(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["init", "--path", str(root), "--approve", "--only-reviewed"]) == 0
    out = capsys.readouterr().out
    assert signed(root) == []
    assert "Found in this project's code but NOT granted (2)" in out
    code = main(["init", "--path", str(root), "--only-reviewed", "--grant-discovered"])
    assert code != 0
    assert "not both" in capsys.readouterr().err
