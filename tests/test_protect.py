"""The one-command path only sequences the guided path, and a person still approves."""

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from anthropic_fixture import MODEL, PRICES, ScriptedProvider, text, tool

from actenon_airlock import protect as protect_module
from actenon_airlock import workflow
from actenon_airlock.cli import main
from actenon_airlock.common import AirlockError
from actenon_airlock.demo import STOLEN, verdict
from actenon_airlock.protect import TASK_FILE, _approved, _new_run, choose_agent
from actenon_airlock.protected import Docker, ProtectedBroker, availability, snapshot
from actenon_airlock.state import State

IMAGE = os.environ.get("AIRLOCK_TEST_CLAUDE_CODE_IMAGE")
COMPUTE = os.environ.get("AIRLOCK_TEST_PROTECTED_IMAGE")
ARGS = ["--agent", "claude-code", "--model", MODEL, "--price-per-mtok", PRICES]
LIVE_TEST = Path(__file__).parents[1] / "acceptance" / "live-github" / "run.py"


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-supervisor-held-test-value")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(protect_module, "ensure_image", lambda *args: None)
    # The plain-English Docker preflight is covered in test_first_run_failures; the real
    # engine check (verify_engine) still runs wherever a test reaches Docker.
    monkeypatch.setattr("actenon_airlock.preflight.require_docker", lambda retry: True)
    # The pre-spend toolchain probe asks the real image when it exists (the container job);
    # without the image these unit tests stand in for it, as they do for ensure_image.
    real_probe = protect_module.missing_tools
    monkeypatch.setattr(
        protect_module,
        "missing_tools",
        lambda image, commands: (
            real_probe(image, commands) if availability(image)["available"] else []
        ),
    )
    return root


def protect(root, *extra, task="Fix add"):
    return main(["protect", "--path", str(root), *ARGS, *extra, task])


def test_the_agent_comes_from_the_key_in_this_shell(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(AirlockError, match="ANTHROPIC_API_KEY or|OPENAI_API_KEY or"):
        choose_agent(None)
    monkeypatch.setenv("OPENAI_API_KEY", "key")
    assert choose_agent(None) == "codex-cli"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    with pytest.raises(AirlockError, match="--agent"):
        choose_agent(None)
    assert choose_agent("claude-code") == "claude-code"


def test_an_agent_without_a_default_path_is_refused(project, capsys):
    assert main(["protect", "--path", str(project), "--agent", "aider", "Fix add"]) == 2
    assert "guided path" in capsys.readouterr().err


def test_a_missing_key_is_named_before_anything_runs(project, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert protect(project) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err
    assert not (project / ".airlock").exists()


@pytest.mark.parametrize("link", [False, True])
def test_a_projects_own_task_file_is_never_replaced(project, link, capsys):
    path = project / TASK_FILE
    if link:
        path.symlink_to(project / "elsewhere")
    else:
        path.write_text("mine\n")
    assert protect(project, "--approve") == 2
    assert TASK_FILE in capsys.readouterr().err
    assert link or path.read_text() == "mine\n"


def test_approval_needs_a_person(project, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert protect(project) == 2
    assert "Approval needs a person" in capsys.readouterr().err
    assert not (project / ".airlock" / "approved.json").exists()


def test_declining_runs_nothing(project, monkeypatch, capsys):
    stream = io.StringIO("n\n")
    stream.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", stream)
    assert protect(project) == 2
    assert "Nothing was approved and nothing ran" in capsys.readouterr().out
    assert not (project / ".airlock" / "approved.json").exists()


def test_the_review_says_what_the_agent_gets(project, monkeypatch, capsys):
    stream = io.StringIO("n\n")
    stream.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", stream)
    protect(project, "--max-run-usd", "3.50")
    shown = capsys.readouterr().out
    assert MODEL in shown and "$3.50" in shown
    # Prices are shown once, in words: input, cache write, cache read and output.
    assert "input $2.00, cache write $2.50, cache read $0.20, output $10.00" in shown
    assert shown.count("Prices for the spend bound") == 1
    assert "no network" in shown and "the agent never sees it" in shown


def test_a_changed_bound_needs_approval_again(project):
    state = State(project)
    config = {"agent": "claude-code", "model": MODEL, "max_run_usd": "2.00"}
    assert not _approved(state, config)
    assert main(["setup", "--path", str(project), *ARGS, "--max-run-usd", "2.00", "--approve"]) == 0
    assert _approved(state, config)
    assert not _approved(state, {**config, "max_run_usd": "9.00"})
    assert not _approved(state, {**config, "model": "another-model"})
    assert not _approved(state, {**config, "model_endpoint": "https://other.example/v1/messages"})


def test_an_earlier_run_is_never_reported_as_this_one(tmp_path):
    state = State(tmp_path)
    runs = state.local / "runs"
    (runs / "old").mkdir(parents=True)
    (runs / "old" / "result.json").write_text("{}")
    earlier = set(runs.iterdir())
    assert _new_run(state, earlier) is None
    (runs / "crashed").mkdir()
    assert _new_run(state, earlier) is None
    (runs / "new").mkdir()
    (runs / "new" / "result.json").write_text("{}")
    assert _new_run(state, earlier).name == "new"


def test_a_failed_run_leaves_no_task_file_and_claims_no_result(project, monkeypatch, capsys):
    def launch(*args, **options):
        raise AirlockError("Protected Mode requires a running local Linux Docker engine")

    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve") == 2
    captured = capsys.readouterr()
    assert not (project / TASK_FILE).exists()
    assert "RESULT" not in captured.out and "git apply" not in captured.out


def test_a_task_file_is_not_part_of_a_candidate(tmp_path):
    (tmp_path / TASK_FILE).write_text("task\n")
    (tmp_path / "keep.txt").write_text("keep\n")
    assert sorted(workflow._tree(tmp_path)) == ["keep.txt"]


def test_status_can_cover_one_run(tmp_path):
    (tmp_path / "main.py").write_text("print('compute only')\n")
    state = State(tmp_path)
    assert main(["init", "--path", str(tmp_path), "--approve", "--command", "main.py"]) == 0
    ProtectedDeny = {"id": "receipt_a", "decision": "DENY", "reason": "first"}
    state.receipt(ProtectedDeny)
    mark = workflow.status(state)["receipts"]
    state.receipt({**ProtectedDeny, "id": "receipt_b", "reason": "second"})
    only = workflow.status(state, since=mark)
    assert only["refused"] == 1 and only["refusal_reasons"] == ["second"]
    assert workflow.status(state)["refused"] == 2


def fake_launch(code=0, exit_code=0, edit=True):
    """Stands in for the containers. Everything after the run is the real path."""
    seen = {}

    def launch(root, command, *, image):
        seen.update(command=command, image=image, task=(root / TASK_FILE).read_text())
        run = State(root).local / "runs" / "protected_fake"
        shutil.copytree(root, run / "workspace", ignore=shutil.ignore_patterns(".airlock"))
        if edit:
            (run / "workspace" / "calculator.py").write_text("def add(a, b):\n    return a + b\n")
        (run / "result.json").write_text(json.dumps({"exit_code": exit_code}))
        return code

    return launch, seen


@pytest.mark.parametrize(
    ("key", "agent", "binary"),
    [("ANTHROPIC_API_KEY", "claude-code", "claude"), ("OPENAI_API_KEY", "codex-cli", "codex")],
)
def test_each_agent_goes_from_a_key_to_a_patch(project, monkeypatch, capsys, key, agent, binary):
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.setenv(key, "held-by-the-supervisor")
    launch, seen = fake_launch()
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert main(["protect", "--path", str(project), "--approve", "Fix add"]) == 0
    shown = capsys.readouterr().out
    assert seen["image"] == protect_module.SUPPORTED[agent]["image"]
    assert any(binary in part for part in seen["command"])
    assert seen["task"] == "Fix add\n"
    assert "git apply .airlock/local/candidates/" in shown and "of $2.00" in shown
    assert "Checks    not run" in shown
    assert not (project / TASK_FILE).exists()
    assert (project / "calculator.py").read_text().endswith("a - b\n")


def test_a_second_run_asks_nothing_and_reports_only_itself(project, monkeypatch, capsys):
    launch, _ = fake_launch()
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve") == 0
    State(project).receipt({"id": "receipt_old", "decision": "DENY", "reason": "earlier"})
    shutil.rmtree(State(project).local / "runs")
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert protect(project) == 0
    assert "Refused   0 attempt(s)" in capsys.readouterr().out


def test_a_refusal_is_reported_and_keeps_its_exit_code(project, monkeypatch, capsys):
    launch, _ = fake_launch(code=3)
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve") == 3
    assert "RESULT" in capsys.readouterr().out


def test_an_agent_that_changed_nothing_gives_no_patch(project, monkeypatch, capsys):
    launch, _ = fake_launch(edit=False)
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve") == 0
    shown = capsys.readouterr().out
    assert "Changed   nothing" in shown and "git apply" not in shown


def test_failing_tests_fail_the_command(project, monkeypatch, capsys, tmp_path):
    launch, _ = fake_launch()
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    monkeypatch.setattr(
        workflow,
        "verify_candidate",
        lambda *args, **options: {"verdict": "TESTS_FAILED", "detail": "1 of 2 tests did not pass"},
    )
    assert protect(project, "--approve", "--tests", str(tmp_path)) == 2
    shown = capsys.readouterr().out
    assert "Checks    FAIL:" in shown and "your checks did not pass (FAIL)" in shown


def test_the_agent_gets_the_projects_docs_and_can_change_them(tmp_path):
    root = tmp_path / "project"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "guide.md").write_text("guide\n")
    snapshot(root, tmp_path / "copy")
    assert (tmp_path / "copy" / "docs" / "guide.md").read_text() == "guide\n"
    assert "docs/guide.md" in workflow._tree(root)


def docker_failing_first(prefix, calls):
    docker = Docker.__new__(Docker)
    docker.host_path_prefix = prefix

    def call(args, *, timeout=45):
        calls.append(args)
        if len(calls) == 1:
            raise AirlockError("Protected Mode Docker operation failed: create")
        return "container"

    docker.call = call
    return docker


def test_docker_desktop_recovers_from_a_stale_view_of_a_recreated_project():
    calls = []
    docker = docker_failing_first("/host_mnt", calls)
    assert docker.create(["create", "x"], project="/project", image="sha256:i") == "container"
    assert calls[0] == calls[2] == ["create", "x"]
    assert calls[1][:3] == ["run", "--rm", "--network"] and calls[1][3] == "none"
    assert "/project/.airlock" in calls[1] and "--read-only" in calls[1]


def test_a_create_failure_on_linux_is_reported_and_never_retried():
    calls = []
    docker = docker_failing_first(None, calls)
    with pytest.raises(AirlockError, match="create"):
        docker.create(["create", "x"], project="/project", image="sha256:i")
    assert len(calls) == 1


def live_test_module():
    spec = importlib.util.spec_from_file_location("live_github_run", LIVE_TEST)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_live_test_refuses_anything_but_a_disposable_private_repository():
    refusal = live_test_module().refusal
    assert refusal({"private": True}, 1) is None
    assert "public" in refusal({"private": False}, 1)
    assert "archived" in refusal({"private": True, "archived": True}, 1)
    assert "disposable" in refusal({"private": True}, 6)


def test_the_live_test_will_not_write_without_being_told(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "held")
    completed = subprocess.run(
        [sys.executable, str(LIVE_TEST), "--repo", "a/b", "--out", str(tmp_path / "out")],
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0 and "--confirm-live-write" in completed.stderr
    assert not (tmp_path / "out").exists()


@pytest.mark.skipif(not COMPUTE, reason="requires the protected compute image")
def test_the_live_test_passes_against_the_synthetic_provider(tmp_path):
    out = tmp_path / "live"
    completed = subprocess.run(
        [sys.executable, str(LIVE_TEST), "--synthetic", "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=280,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads((out / "summary.json").read_text())
    assert summary["evidence_class"] == "synthetic" and summary["passed"]
    assert all(summary["checks"].values()) and len(summary["checks"]) == 9
    assert summary["patch_sha256"] == summary["provider_bytes_sha256"]
    assert sorted(path.name for path in (out / "evidence").iterdir()) == [
        "public-key.json",
        "receipts.jsonl",
    ]


def test_the_demo_claims_nothing_if_the_control_failed():
    everything = set(STOLEN)
    good = {"control_fixed": True, "protected_fixed": True}
    assert verdict(control=everything, protected=set(), **good) == []
    assert "did not land" in verdict(control=everything - {"token"}, protected=set(), **good)[0]
    assert "reached the sink" in verdict(control=everything, protected={"direct"}, **good)[0]
    bad = {"control_fixed": True, "protected_fixed": False}
    assert "did not finish" in verdict(control=everything, protected=set(), **bad)[0]


@pytest.mark.skipif(not IMAGE, reason="requires the Claude Code compute image")
def test_protect_takes_a_task_to_a_reviewed_patch(tmp_path, monkeypatch, capsys):
    root = tmp_path / "project"
    root.mkdir()
    original = "def add(a, b):\n    return a - b\n"
    (root / "calculator.py").write_text(original)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "test_add.py").write_text(
        "from calculator import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-supervisor-held-test-value")
    provider = ScriptedProvider(
        [
            [tool("t1", "Read", file_path=f"/workspace/{TASK_FILE}")],
            [
                tool(
                    "t2",
                    "Edit",
                    file_path="/workspace/calculator.py",
                    old_string="a - b",
                    new_string="a + b",
                ),
            ],
            [tool("t3", "Bash", command="cat /etc/hostname", description="Look around")],
            [text("Fixed.")],
        ]
    )
    wrapped = ProtectedBroker.__init__

    def initialize(self, *args, **kwargs):
        import httpx

        wrapped(self, *args, **kwargs)
        self.http.close()
        self.http = httpx.Client(transport=httpx.MockTransport(provider))

    monkeypatch.setattr(ProtectedBroker, "__init__", initialize)
    code = main(
        ["protect", "--path", str(root), *ARGS, "--max-run-usd", "5", "--image", IMAGE]
        + ["--tests", str(trusted), "--approve", "Fix add so the tests pass"]
    )
    shown = capsys.readouterr().out
    if os.environ.get("AIRLOCK_SHOW_PROTECT_OUTPUT"):
        Path(os.environ["AIRLOCK_SHOW_PROTECT_OUTPUT"]).write_text(shown)
    assert code == 0, shown
    assert "RESULT" in shown and "Checks    PASS: 1 test passed" in shown and "git apply" in shown
    # The real container's stream became short lines; the raw stream is in the log only.
    assert '{"type"' not in shown and "AIRLOCK ALLOW" not in shown
    for line in ("started   ", "reading   AIRLOCK_TASK.md", "editing   calculator.py",
                 "running   Look around", "The agent says: Fixed."):  # fmt: skip
        assert line in shown, line
    log = next(Path(root, ".airlock/local/logs").glob("protect-*.log")).read_text()
    assert '"type":"system"' in log and "AIRLOCK ALLOW" in log
    assert "modified calculator.py" in " ".join(shown.split())
    assert "Refused   0 attempt(s)" in shown
    assert (root / "calculator.py").read_text() == original
    assert not (root / TASK_FILE).exists()
    patch = next(Path(root, ".airlock/local/candidates").glob("*/candidate.patch"))
    assert TASK_FILE not in patch.read_text()
    subprocess.run(["git", "-C", str(root), "apply", str(patch)], check=True)
    assert "a + b" in (root / "calculator.py").read_text()


@pytest.mark.skipif(not COMPUTE, reason="requires the protected compute image")
def test_the_demo_runs_with_its_control_and_cleans_up(capsys):
    def networks():
        listed = subprocess.run(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return {name for name in listed.stdout.split() if name.startswith("airlock-demo-")}

    before = networks()
    assert main(["demo"]) == 0
    shown = capsys.readouterr().out
    assert shown.count("LEAKED") == len(STOLEN)
    assert f"Reached the sink: {len(STOLEN)} from the ordinary container, 0 from" in shown
    # Part 2: the sealed run's real candidate, checked, approved exactly, sent once, verified.
    assert shown.count("REFUSED, nothing sent") == 2
    assert "REFUSED: it would duplicate" in shown
    # The stand-in is never presented as real GitHub.
    assert "1 file created on the local stand-in, confirmed independently" in shown
    assert "Nothing was written to real GitHub" in shown
    assert "created on GitHub" not in shown and "read GitHub back" not in shown
    assert "What you just saw" in shown and "0 out of Protected Mode" in shown
    assert "\033[" not in shown  # no colour codes when the output is not a terminal
    assert "Outcome    CONFIRMED (from airlock explain)" in shown
    assert "claims nothing" not in shown
    assert "mkdir -p ~/airlock-practice" in shown and "costs money" in shown
    assert networks() == before


def test_protect_refuses_a_home_folder_before_anything_else(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home" / "you"
    (home / "code" / "app").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    # No key and no Docker needed to be told: the folder is checked first.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    for folder in (home, home.parent, Path("/")):
        assert main(["protect", "--path", str(folder), "Fix it"]) != 0
        err = capsys.readouterr().err
        assert "is not one. Nothing ran." in err and "cd into the project first" in err, err
        assert not (folder / ".airlock").exists() or folder == Path("/")
    assert not (home / ".airlock").exists() and not (home / TASK_FILE).exists()
    assert protect_module.broad_folder(home / "code" / "app") is None


def test_the_demo_says_what_the_real_thing_needs():
    from actenon_airlock.demo import NEXT_STEP

    assert "path/to" not in NEXT_STEP  # every line can be pasted as it is
    assert "skip to" not in NEXT_STEP  # own projects are not pointed at the practice tests
    assert "mkdir -p ~/airlock-practice && cd ~/airlock-practice" in NEXT_STEP
    assert 'airlock protect --tests ~/airlock-practice-tests "Fix the failing test"' in NEXT_STEP
    assert "ANTHROPIC_API_KEY" in NEXT_STEP and "never enters the container" in NEXT_STEP
    words = " ".join(NEXT_STEP.split())
    assert "costs money" in words and "runs nothing until you approve" in words


STREAM = [
    '{"type":"system","subtype":"init","model":"claude-opus-5-5","tools":["Bash"]}',
    '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash",'
    '"input":{"command":"python -m pytest -q","description":"Run the tests"}}]}}',
    '{"type":"user","message":{"content":[{"type":"tool_result","content":'
    '"F\\nFAILED test_calculator.py::test_add - assert -1 == 5\\n1 failed in 0.01s"}]}}',
    '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Edit",'
    '"input":{"file_path":"/workspace/calculator.py"}}]}}',
    '{"type":"result","num_turns":4,"result":"I fixed the failing test."}',
]


def test_a_run_shows_short_progress_and_keeps_the_full_transcript(project, monkeypatch, capsys):
    def launch(root, command, *, image):
        run = State(root).local / "runs" / "protected_fake"
        shutil.copytree(root, run / "workspace", ignore=shutil.ignore_patterns(".airlock"))
        (run / "workspace" / "calculator.py").write_text("def add(a, b):\n    return a + b\n")
        (run / "result.json").write_text(json.dumps({"exit_code": 0}))
        # The way the real run writes: the container on fd 1, the supervisor on stderr.
        for line in STREAM[:3]:
            os.write(1, (line + "\n").encode())
        print("AIRLOCK ALLOW http.post @ https://api.anthropic.com/v1/messages: x [r1]",
              file=sys.stderr)  # fmt: skip
        subprocess.run([sys.executable, "-c", f"print({STREAM[3]!r}); print({STREAM[4]!r})"])
        return 0

    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve") == 0
    shown = capsys.readouterr().out
    assert '{"type"' not in shown and "AIRLOCK ALLOW" not in shown
    for line in ("started   claude-opus-5-5", "running   Run the tests", "→ 1 failed in 0.01s",
                 "editing   calculator.py", "The agent says: I fixed the failing test.",
                 "its own words", "Full agent transcript: .airlock/local/logs/protect-"):  # fmt: skip
        assert line in shown, line
    logs = list((project / ".airlock/local/logs").glob("protect-*.log"))
    assert len(logs) == 1 and oct(logs[0].stat().st_mode)[-3:] == "600"
    raw = logs[0].read_text()
    assert all(line in raw for line in STREAM) and "AIRLOCK ALLOW" in raw
    # The receipt that follows is Airlock's, printed normally.
    assert "RESULT" in shown and "Changed   1 file(s)" in shown


def test_nothing_changed_says_why_the_checks_did_not_run(project, monkeypatch, capsys, tmp_path):
    launch, _ = fake_launch(edit=False)
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve", "--tests", str(tmp_path)) == 0
    shown = capsys.readouterr().out
    assert "The agent finished but changed nothing." in shown
    assert "Checks    not run: the agent changed nothing, so there was nothing to check" in shown
    assert "Pass --tests DIR" not in shown


def test_the_evidence_line_counts_this_run_apart_from_earlier_ones(project, monkeypatch, capsys):
    launch, _ = fake_launch()
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve") == 0
    first = capsys.readouterr().out
    assert "signed receipt(s) from this run, integrity OK" in first
    shutil.rmtree(State(project).local / "runs")  # the stand-in reuses one run folder
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert protect(project) == 0
    second = capsys.readouterr().out
    line = next(line for line in second.splitlines() if line.startswith("  Evidence"))
    this_run, total = (int(word) for word in line.replace("(", " ").split() if word.isdigit())
    assert 0 < this_run < total and "in this project's journal" in line


def test_a_missing_key_names_the_agent_this_project_is_set_up_for(project, monkeypatch, capsys):
    launch, _ = fake_launch()
    monkeypatch.setattr("actenon_airlock.protected.launch_protected", launch)
    assert protect(project, "--approve") == 0
    capsys.readouterr()
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(["protect", "--path", str(project), "Fix add"]) != 0
    err = capsys.readouterr().err
    assert "This project is set up for claude-code. Set ANTHROPIC_API_KEY" in err
    assert "OPENAI_API_KEY" not in err and "--agent" in err


def test_a_new_project_without_a_key_still_offers_both_agents(tmp_path, monkeypatch, capsys):
    root = tmp_path / "fresh"
    root.mkdir()
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(["protect", "--path", str(root), "Fix add"]) != 0
    assert "OPENAI_API_KEY or ANTHROPIC_API_KEY" in capsys.readouterr().err
