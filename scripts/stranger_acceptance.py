"""Stranger-install acceptance: the documented first-run journey, from nothing, with timings.

Run it on your own machine to see what a newcomer sees:

    python3 scripts/stranger_acceptance.py --output stranger-acceptance.json

It uses a fresh HOME and a fresh pipx location, installs exactly the commit the README
installs, and runs only the commands the docs give a newcomer. Every step ends PASS, FAIL,
BLOCKED (could not be exercised here, with the reason) or SIMULATED (a failure state produced
without changing this machine, for example a Docker that is not running). A BLOCKED step is
never counted as a pass. Nothing is published, no model is called and no key is used.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_readme_install", ROOT / "scripts" / "check_readme_install.py"
)
docs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(docs)

IMAGES = ("actenon-airlock-compute:dev", "actenon-airlock-claude-code:v1")
BASE = "python@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5"
PRACTICE = r"""
mkdir -p "$HOME/airlock-practice" && cd "$HOME/airlock-practice"
printf 'def add(a, b):\n    return a - b\n' > calculator.py
printf 'from calculator import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n' > test_calculator.py
mkdir -p "$HOME/airlock-practice-tests" && cp test_calculator.py "$HOME/airlock-practice-tests/"
"""


class Journey:
    def __init__(self, env: dict, cwd: Path):
        self.env, self.cwd, self.steps = env, cwd, []

    def record(self, step: str, status: str, seconds: float | None, detail: str) -> None:
        self.steps.append(
            {"step": step, "status": status, "seconds": seconds, "detail": detail.strip()}
        )
        mark = f"{seconds:>6.1f}s" if seconds is not None else "       "
        print(f"{status:<10} {mark}  {step}: {detail.strip().splitlines()[0][:90]}", flush=True)

    def run(self, cmd, *, env=None, timeout=1800, cwd=None):
        start = time.monotonic()
        result = subprocess.run(
            cmd, env=env or self.env, cwd=cwd or self.cwd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )  # fmt: skip
        return result, round(time.monotonic() - start, 1)


def docker_facts() -> dict:
    docker = shutil.which("docker")
    if not docker:
        return {"available": False}

    def present(name: str) -> bool:
        return (
            subprocess.run([docker, "image", "inspect", name], capture_output=True).returncode == 0
        )

    info = subprocess.run(
        [docker, "info", "--format", "{{.ServerVersion}} {{.OperatingSystem}}"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    return {
        "available": info.returncode == 0,
        "engine": info.stdout.strip(),
        "airlock_images_present_before": [name for name in IMAGES if present(name)],
        "base_image_cached_before": present(BASE),
    }


def demo_checks(out: str) -> list[tuple[str, bool, str]]:
    """What the demo's own output must show, step by step."""
    return [
        ("4 authority review", "proposes one grant" in out and "not granted" in out,
         "the one exact grant is shown, and what was found but not granted"),
        ("5 refusal controls", out.count("nothing got out") == 4
         and out.count("REFUSED") >= 4, "4 exfiltration attempts stopped, 4 refusals shown"),
        ("6 approved synthetic consequence", "sent once, held as unconfirmed" in out
         and "REFUSED: it would duplicate" in out, "sent once to the local stand-in; replay refused"),
        ("7 independent readback", "CONFIRMED" in out and "bytes, parent and path match" in out,
         "readback CONFIRMED and the independent check matched"),
        ("8 receipt verification", bool(re.search(r"\d+ signed receipts, integrity OK", out)),
         "the signed journal verified"),
    ]  # fmt: skip


def journey(commit: str, python: str | None) -> dict:
    pipx = shutil.which("pipx")
    facts = {
        "commit": commit,
        "os": {"Darwin": "macOS"}.get(platform.system(), platform.system()),
        "machine": platform.machine(),
        "docker": docker_facts(),
    }
    with tempfile.TemporaryDirectory(prefix="airlock-stranger-") as tmp:
        home = Path(tmp) / "home"
        home.mkdir()
        env = docs.clean_environment(home)
        j = Journey(env, home)
        if not pipx:
            j.record("1 documented install", "BLOCKED", None, "pipx is not installed here")
            return {**facts, "steps": j.steps}
        command = [pipx, "install", f"git+{docs.REPO_URL}@{commit}"]
        if python:
            command[2:2] = ["--python", python]
        result, took = j.run(command)
        if result.returncode:
            j.record("1 documented install", "FAIL", took, (result.stdout + result.stderr)[-800:])
            return {**facts, "steps": j.steps}
        j.record("1 documented install", "PASS", took, " ".join(["pipx", *command[1:]]))

        result, took = j.run(["airlock", "doctor", "--json"])
        report = json.loads(result.stdout or "{}")
        facts["python"] = (report.get("system") or {}).get("python")
        ready = report.get("ready") and report.get("airlock", {}).get("commit") == commit
        if not facts["docker"]["available"]:
            j.record("2 doctor", "BLOCKED", took, "Docker is not running here; doctor said: "
                     + str(report.get("next_step")))  # fmt: skip
            return {**facts, "steps": j.steps}
        j.record("2 doctor", "PASS" if ready else "FAIL", took,
                 f"ready={report.get('ready')} installed commit={report.get('airlock')}")  # fmt: skip

        cold = not facts["docker"]["airlock_images_present_before"]
        result, took = j.run(["airlock", "demo"])
        out = result.stdout
        ok = result.returncode == 0 and "claims nothing" not in out and "What you just saw" in out
        label = "cold images" if cold else "images already built"
        j.record("3 free demo", "PASS" if ok else "FAIL", took, f"first run, {label}")
        for step, passed, what in demo_checks(out):
            j.record(step, "PASS" if passed and ok else "FAIL", None, what)

        result, took = j.run(["bash", "-c", PRACTICE])
        project, tests = home / "airlock-practice", home / "airlock-practice-tests"
        keyless = {k: v for k, v in env.items() if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")}
        result, took = j.run(
            ["airlock", "protect", "--tests", str(tests), "Fix the failing test"],
            env=keyless, cwd=project,
        )  # fmt: skip
        said = result.stderr + result.stdout
        guided = result.returncode == 2 and re.search(r"Set (OPENAI|ANTHROPIC)_API_KEY", said)
        untouched = not (project / ".airlock").exists()
        j.record("9 practice project, no key", "PASS" if guided and untouched else "FAIL", took,
                 "the documented project; without a key Airlock says which key to set and "
                 "creates nothing")  # fmt: skip
        j.record("9 practice project, real model", "BLOCKED", None,
                 "needs an owner-authorised model key and spend limit; never run by this script")  # fmt: skip

        result, took = j.run(["airlock", "demo"])
        ok = result.returncode == 0 and "claims nothing" not in result.stdout
        j.record("10 repeat demo", "PASS" if ok else "FAIL", took, "second run, images built")

        proc = subprocess.Popen(
            ["airlock", "demo"], env=env, cwd=home, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )  # fmt: skip
        time.sleep(2)
        proc.send_signal(signal.SIGINT)
        _, err = proc.communicate(timeout=120)
        time.sleep(1)
        left = subprocess.run(
            ["docker", "ps", "-aq", "--filter", "name=airlock-demo"], capture_output=True, text=True
        ).stdout.split() + subprocess.run(
            ["docker", "network", "ls", "-q", "--filter", "name=airlock-demo"],
            capture_output=True, text=True,
        ).stdout.split()  # fmt: skip
        clean = proc.returncode in (130, 0) and not left and "Traceback" not in err
        j.record("10 interrupted demo (Ctrl-C at 2s)", "PASS" if clean else "FAIL", None,
                 f"exit {proc.returncode}, {len(left)} container/network left; "
                 + (err.strip().splitlines() or ["(finished first)"])[-1])  # fmt: skip

        dead = {**env, "DOCKER_HOST": "unix:///nonexistent/airlock-acceptance.sock"}
        result, took = j.run(["airlock", "demo"], env=dead)
        explained = (
            result.returncode == 2 and "Docker is installed but not running" in result.stderr
        )
        j.record("10 Docker not running", "SIMULATED" if explained else "FAIL", took,
                 "DOCKER_HOST pointed at a missing socket; Docker itself was not stopped")  # fmt: skip

        result, took = j.run([pipx, "uninstall", "actenon-airlock"])
        j.record("cleanup", "PASS" if result.returncode == 0 else "FAIL", took,
                 "pipx uninstall; the temporary HOME is deleted")  # fmt: skip
        return {**facts, "steps": j.steps}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--commit", help="default: the commit every guide installs")
    parser.add_argument("--python", help="pipx --python, for example python3.11")
    parser.add_argument("--output", type=Path, help="write the JSON result here")
    args = parser.parse_args(argv)
    commit = args.commit or docs.check_documents()
    started = time.monotonic()
    result = journey(commit, args.python)
    result["total_seconds"] = round(time.monotonic() - started, 1)
    counts = {}
    for step in result["steps"]:
        counts[step["status"]] = counts.get(step["status"], 0) + 1
    result["summary"] = counts
    print(json.dumps({"summary": counts, "total_seconds": result["total_seconds"]}))
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    return 1 if counts.get("FAIL") else 0


if __name__ == "__main__":
    os.environ.pop("PYTHONPATH", None)
    raise SystemExit(main())
