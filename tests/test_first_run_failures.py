"""Every common first-run failure says what is wrong, that nothing happened, and what to do.

A fake `docker` on PATH stands in for each broken Docker state, so these run anywhere.
The real-engine paths are covered by the container suites.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from actenon_airlock import preflight, style
from actenon_airlock.cli import doctor, doctor_text, main

INFO_OK = {"OSType": "linux", "SecurityOptions": ["name=seccomp,profile=builtin"]}
CONTEXT = [{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]
LEAK = "supersecret-daemon-detail"


def fake_docker(tmp_path: Path, monkeypatch, *, info=None, info_exit=0, stderr="", sleep=0):
    """Put a `docker` on PATH that answers `context inspect` and `info` as told."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "docker"
    script.write_text(
        "#!/bin/sh\n"
        f"if [ \"$1\" = context ]; then echo '{json.dumps(CONTEXT)}'; exit 0; fi\n"
        f"sleep {sleep}\n"
        f"echo '{stderr}' >&2\n"
        f"echo '{json.dumps(info if info is not None else INFO_OK)}'\n"
        f"exit {info_exit}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)


def test_docker_not_installed(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    problem = preflight.docker_problem("airlock demo")
    assert problem.category == "DOCKER_NOT_INSTALLED"
    text = problem.render()
    assert "Docker is not installed" in text and "Nothing ran and nothing was changed" in text
    assert "airlock demo" in text and "#docker-is-not-installed" in text


@pytest.mark.parametrize(
    "stderr, category",
    [
        ("Cannot connect to the Docker daemon. Is the docker daemon running?", "DOCKER_NOT_RUNNING"),
        ("permission denied while trying to connect to the Docker daemon socket", "DOCKER_PERMISSION_DENIED"),
    ],
)  # fmt: skip
def test_docker_installed_but_unusable(tmp_path, monkeypatch, stderr, category):
    fake_docker(tmp_path, monkeypatch, info_exit=1, stderr=f"{stderr} {LEAK}")
    problem = preflight.docker_problem("airlock demo")
    assert problem.category == category
    assert LEAK not in problem.render()  # Docker's own text is never shown


def test_docker_that_does_not_answer(tmp_path, monkeypatch):
    fake_docker(tmp_path, monkeypatch, sleep=3)
    problem = preflight.docker_problem("airlock demo", timeout=0.5)
    assert problem.category == "DOCKER_NOT_RESPONDING"
    assert "did not answer" in problem.what


def test_remote_engine_is_refused_without_printing_where(tmp_path, monkeypatch):
    fake_docker(tmp_path, monkeypatch)
    monkeypatch.setenv("DOCKER_HOST", f"tcp://user:{LEAK}@build.example:2376")
    problem = preflight.docker_problem("airlock demo")
    assert problem.category == "DOCKER_REMOTE_ENGINE"
    assert LEAK not in problem.render() and "build.example" not in problem.render()


@pytest.mark.parametrize(
    "info, category",
    [
        ({"OSType": "windows", "SecurityOptions": []}, "DOCKER_NOT_LINUX"),
        ({"OSType": "linux", "SecurityOptions": ["name=seccomp,profile=unconfined"]}, "DOCKER_NO_SECCOMP"),
    ],
)  # fmt: skip
def test_engines_airlock_cannot_use(tmp_path, monkeypatch, info, category):
    fake_docker(tmp_path, monkeypatch, info=info)
    assert preflight.docker_problem("airlock demo").category == category


def test_a_working_engine_has_no_problem(tmp_path, monkeypatch):
    fake_docker(tmp_path, monkeypatch)
    assert preflight.docker_problem("airlock demo") is None


def test_demo_stops_before_building_anything(tmp_path, monkeypatch, capsys):
    import actenon_airlock.demo as demo

    fake_docker(tmp_path, monkeypatch, info_exit=1, stderr="Cannot connect to the Docker daemon")
    built = []
    monkeypatch.setattr(demo, "ensure_image", lambda *a: built.append(a))
    assert main(["demo"]) == 2
    err = capsys.readouterr().err
    assert "Docker is installed but not running" in err and "airlock demo" in err
    assert not built


def test_protect_stops_before_images_approval_or_spend(tmp_path, monkeypatch, capsys):
    import actenon_airlock.protect as protect

    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-" + "x" * 80)
    fake_docker(tmp_path, monkeypatch, info_exit=1, stderr="Cannot connect to the Docker daemon")
    built = []
    monkeypatch.setattr(protect, "ensure_image", lambda *a: built.append(a))
    code = main(["protect", "--path", str(root), "--agent", "claude-code", "Fix it"])
    err = capsys.readouterr().err
    assert code == 2 and "Docker is installed but not running" in err
    assert "airlock protect 'Fix it'" in err
    assert not built and not (root / ".airlock").exists()


def test_protect_refuses_checks_the_image_cannot_run_before_any_spend(
    tmp_path, monkeypatch, capsys
):
    import actenon_airlock.protect as protect

    root = tmp_path / "service"
    root.mkdir()
    (root / "go.mod").write_text("module example.com/service\n\ngo 1.22\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-" + "x" * 80)
    monkeypatch.setattr("actenon_airlock.preflight.require_docker", lambda retry: True)
    monkeypatch.setattr(protect, "ensure_image", lambda *a: None)
    monkeypatch.setattr(protect, "missing_tools", lambda image, commands: ["go"])
    asked = []
    monkeypatch.setattr(protect, "_ask", lambda: asked.append(1) or True)
    code = main(
        ["protect", "--path", str(root), "--agent", "claude-code", "--tests", str(tests), "Fix it"]
    )
    err = capsys.readouterr().err
    assert code == 2
    assert "This looks like a Go project" in err and "`go`" in err
    assert "Nothing ran and nothing was spent" in err and "--image" in err
    assert not asked and not (root / ".airlock" / "approved.json").exists()


def test_doctor_without_docker_says_what_still_works(tmp_path, monkeypatch):
    fake_docker(tmp_path, monkeypatch, info_exit=1, stderr="Cannot connect to the Docker daemon")
    result = doctor(tmp_path)
    assert result["ok"] and not result["ready"]
    assert result["docker"]["category"] == "DOCKER_NOT_RUNNING"
    assert all(a["image_ready"] is None for a in result["agents"].values())
    text = doctor_text(result)
    assert "Not ready for `airlock demo` or `airlock protect`" in text
    assert "Images       unknown until Docker is running" in text
    assert "Local Mode (`airlock init` and `airlock run`) works without Docker." in text


def test_doctor_names_the_installed_commit(monkeypatch):
    sha = "0123456789abcdef0123456789abcdef01234567"

    class Dist:
        def read_text(self, name):
            assert name == "direct_url.json"
            return json.dumps({"vcs_info": {"vcs": "git", "commit_id": sha}})

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: Dist())
    assert preflight.installed_commit() == sha
    assert preflight.help_link("docker-is-not-running") == (
        f"https://github.com/Actenon/actenon-airlock/blob/{sha}"
        "/docs/troubleshooting.md#docker-is-not-running"
    )


def test_every_help_link_has_a_troubleshooting_section():
    """The anchors printed by preflight exist in docs/troubleshooting.md."""
    import re

    text = (Path(__file__).resolve().parents[1] / "docs" / "troubleshooting.md").read_text()
    anchors = {
        re.sub(r"[^a-z0-9 -]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
        for line in text.splitlines()
        if line.startswith("## ") or line.startswith("### ")
    }
    source = Path(preflight.__file__).read_text()
    used = set(re.findall(r'"(docker-[a-z-]+)"', source))
    assert used and used <= anchors, used - anchors


@pytest.mark.parametrize(
    "env, tty, expected",
    [({}, True, True), ({"NO_COLOR": "1"}, True, False), ({}, False, False),
     ({"FORCE_COLOR": "1"}, False, True), ({"TERM": "dumb"}, True, False)],
)  # fmt: skip
def test_colour_only_on_a_real_terminal(monkeypatch, env, tty, expected):
    for name in ("NO_COLOR", "FORCE_COLOR", "TERM"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    class Stream:
        def isatty(self):
            return tty

    assert style.enabled(Stream()) is expected
    assert (style.paint("PASS", "good", Stream()) != "PASS") is expected
