import json
import subprocess
import sys

from actenon_airlock import adapters
from actenon_airlock.cli import main
from actenon_airlock.state import State

LOCAL_TOUCH = {"action": "process.exec", "resource": "touch", "transport": "local-process"}


def run(state, timeout=60):
    return subprocess.run(
        [sys.executable, "-m", "actenon_airlock.cli", "run", "--path", str(state.root)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def receipts(state):
    return [json.loads(line) for line in state.receipts_path.read_text().splitlines()]


def final(rows, prefix):
    return [r for r in rows if r["action"].startswith(prefix) and r.get("stage") != "authorized"]


def test_approved_process_is_released_with_kernel_receipt(project):
    state = project('import subprocess\nsubprocess.run(["touch", "made.txt"], check=True)\n')
    assert LOCAL_TOUCH in State(state.root).approved()["powers"]
    result = run(state)
    assert result.returncode == 0, result.stderr
    assert (state.root / "made.txt").exists()
    [row] = final(receipts(state), "process.")
    assert row["decision"] == "ALLOW" and row["stage"] == "released"
    assert row["detail"]["program"] == "touch" and row["detail"]["shell"] is False
    assert row["kernel"]["receipt"]["outcome"] == "executed"
    assert row["credential_released"] is False and row["execution_occurred"] is None
    assert row["evidence"] == {"file": "main.py", "line": 2, "end_line": 2, "col": 1}
    assert "AIRLOCK ALLOW process.exec" in result.stderr


def test_unapproved_process_is_denied_before_spawn(project):
    state = project("print('baseline')\n")
    (state.root / "main.py").write_text(
        'import subprocess\nsubprocess.run(["touch", "made.txt"])\n'
    )
    result = run(state)
    assert result.returncode == 3
    assert not (state.root / "made.txt").exists()
    row = receipts(state)[-1]
    assert row["decision"] == "DENY" and row["action"] == "process.exec"
    assert row["permit_decision"]["outcome"] == "DENY"
    assert row["execution_occurred"] is False


def test_plain_shell_text_binds_to_the_program_scan_named(project):
    state = project('import subprocess\nsubprocess.run("touch made.txt", shell=True, check=True)\n')
    result = run(state)
    assert result.returncode == 0, result.stderr
    [row] = final(receipts(state), "process.")
    assert row["detail"]["shell"] is True and row["detail"]["program"] == "touch"


def test_shell_syntax_fails_closed_even_when_scan_names_the_first_program(project):
    state = project('import os\nos.system("touch a.txt; touch b.txt")\n')
    assert LOCAL_TOUCH in State(state.root).approved()["powers"]
    result = run(state)
    assert result.returncode == 3
    assert not (state.root / "a.txt").exists() and not (state.root / "b.txt").exists()
    row = receipts(state)[-1]
    assert row["decision"] == "DENY" and row["detail"]["program"] == "sh"


def test_unresolved_effects_do_not_block_launch_and_deny_per_call(project):
    state = project(
        "from pathlib import Path\n"
        'Path("approved.txt").write_text("ok")\n'
        'name = "".join(reversed("txt.cimanyd"))\n'
        "try:\n"
        '    open(name, "w").write("no")\n'
        "except PermissionError as exc:\n"
        '    print("handled:", exc)\n'
        'Path("after.txt").write_text("ok")\n'
    )
    approved = State(state.root).approved()
    assert [b["state"] for b in approved["blocked"]] == ["UNRESOLVED"]
    result = run(state)
    # The agent kept running after the denial; Airlock still reports it.
    assert result.returncode == 3, result.stderr
    assert "handled: AIRLOCK BLOCKED" in result.stdout
    assert (state.root / "approved.txt").exists() and (state.root / "after.txt").exists()
    assert not (state.root / "dynamic.txt").exists()
    rows = receipts(state)
    deny = [r for r in rows if r["decision"] == "DENY"]
    assert [(d["action"], d["target"]) for d in deny] == [
        ("filesystem.write", str(state.root / "dynamic.txt"))
    ]
    assert deny[0]["permit_decision"]["outcome"] == "DENY"
    assert len(final(rows, "filesystem.")) == 3


def test_scan_named_tree_operation_is_one_effect(project):
    state = project('import shutil\nshutil.rmtree("build")\n')
    (state.root / "build" / "sub").mkdir(parents=True)
    (state.root / "build" / "sub" / "f.txt").write_text("x")
    result = run(state)
    assert result.returncode == 0, result.stderr
    assert not (state.root / "build").exists()
    rows = [r for r in receipts(state) if r["action"].startswith("filesystem.")]
    assert [(r["action"], r["stage"]) for r in rows] == [
        ("filesystem.delete", "authorized"),
        ("filesystem.delete", "released"),
    ]


def test_mkdir_parents_is_one_effect(project):
    state = project('from pathlib import Path\nPath("a/b/c").mkdir(parents=True)\n')
    result = run(state)
    assert result.returncode == 0, result.stderr
    assert (state.root / "a" / "b" / "c").is_dir()
    [row] = final(receipts(state), "filesystem.")
    assert row["target"] == str(state.root / "a" / "b" / "c")


def test_agent_cannot_write_airlock_state(project):
    state = project('open(".airlock/approved.json", "w").write("{}")\n')
    assert State(state.root).approved()["powers"] == []
    before = (state.path / "approved.json").read_bytes()
    result = run(state)
    assert result.returncode == 3
    assert (state.path / "approved.json").read_bytes() == before
    assert receipts(state)[-1]["reason"] == "Airlock state is not writable by the agent"


def test_writing_through_a_symlink_is_refused(project, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "target.txt"
    state = project('open("link.txt", "w").write("x")\n')
    (state.root / "link.txt").symlink_to(outside)
    result = run(state)
    assert result.returncode == 3
    assert not outside.exists()


def test_email_is_intercepted_and_denied_in_scan_vocabulary(project):
    state = project(
        'import smtplib\nsmtplib.SMTP("smtp.example.com").sendmail("a@x", ["b@x"], "hi")\n'
    )
    assert "No execution adapter" in State(state.root).approved()["blocked"][0]["reason"]
    result = run(state)
    assert result.returncode == 3
    row = receipts(state)[-1]
    assert (row["action"], row["decision"]) == ("email.send", "DENY")
    assert row["target"] == "smtp://smtp.example.com:0"


def test_power_kind_without_adapter_refuses_launch(project, monkeypatch, capsys):
    state = project('import smtplib\nsmtplib.SMTP("smtp.example.com").sendmail("a", ["b"], "c")\n')
    monkeypatch.delitem(adapters.REGISTRY, "email")
    assert main(["run", "--path", str(state.root)]) == 2
    assert "launch is refused: email.send" in capsys.readouterr().err
    assert not state.receipts_path.exists()


def test_receipts_are_signed_chained_and_tamper_evident(project, capsys):
    state = project('from pathlib import Path\nPath("out.txt").write_text("ok")\n')
    assert run(state).returncode == 0
    capsys.readouterr()
    assert main(["receipts", "--path", str(state.root)]) == 0
    out = capsys.readouterr().out
    assert "2 of 2 verified against .airlock/public-key.json" in out
    assert "filesystem.write" in out and "released; execution unobserved" in out
    lines = state.receipts_path.read_text().splitlines()
    rows = [json.loads(line) for line in lines]
    assert rows[-1]["execution_occurred"] is None
    assert rows[0]["prev"] is None and rows[1]["prev"] is not None
    assert rows[1]["signature"]["algorithm"] == "EdDSA"

    tampered = dict(rows[-1], target="/elsewhere")
    state.receipts_path.write_text(lines[0] + "\n" + json.dumps(tampered) + "\n")
    assert main(["receipts", "--path", str(state.root), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["rows"][-1]["problem"].startswith("signature does not verify")

    state.receipts_path.write_text(lines[1] + "\n")
    assert main(["receipts", "--path", str(state.root), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["rows"][0]["problem"].startswith("hash chain")


def test_legitimate_in_project_rename_remains_usable(project):
    state = project(
        "import os\nos.rename('source.txt', 'out.txt')\nassert open('out.txt').read() == 'ordinary data'\n"
    )
    (state.root / "source.txt").write_text("ordinary data")
    assert run(state).returncode == 0
    assert (state.root / "out.txt").read_text() == "ordinary data"


def test_private_file_cannot_be_renamed_to_a_readable_alias(project):
    state = project("import os\nos.rename('.env', 'out.txt')\nprint(open('out.txt').read())\n")
    (state.root / ".env").write_text("PRIVATE_TEST_VALUE=not-a-real-secret\n")
    assert run(state).returncode == 3
    assert (state.root / ".env").exists()
    assert not (state.root / "out.txt").exists()
