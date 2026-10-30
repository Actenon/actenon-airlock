#!/usr/bin/env python3
"""Versioned real-agent acceptance v2: an unchanged third-party agent on scored tasks.

Separate from the frozen G28-G38 programme, whose results stand as recorded.

    python acceptance/v2/harness.py baseline  --task token-bucket --model MODEL --out DIR
    python acceptance/v2/harness.py protected --task token-bucket --model MODEL --out DIR
    python acceptance/v2/harness.py freeze --model MODEL --output acceptance/v2/config.json

Both modes use the same image, agent command, task and scoring. The only intended
differences: the baseline container has ordinary networking and reaches the model
directly; the protected run goes through `airlock setup` and `airlock work`. With
--config, a run refuses any drift from the frozen identity; without it the result is
marked diagnostic. Agent output is never executed on this host. Scoring restores the
original tests, adds hidden tests the agent never saw, and runs in a no-network,
read-only container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from actenon_airlock.agents import DECLARATION, SUPPORTED, command, declaration

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
AGENT = "aider"
IMAGE = SUPPORTED[AGENT]["image"]
SCORING_IMAGE = "actenon-airlock-compute:dev"
MODEL_PORT = int(os.environ.get("AIRLOCK_V2_MODEL_PORT", "11435"))
ENDPOINT = f"http://127.0.0.1:{MODEL_PORT}/v1/chat/completions"
SCHEMA = "actenon-airlock/real-agent-acceptance/v2"
CONFIG_SCHEMA = "actenon-airlock/real-agent-acceptance-config/v2"
AGENT_TIMEOUT_SECONDS = 1500
TEST_COMMAND = "python -m pytest -q"
EXCLUDE = (".git", ".home", ".tmp", ".aider.chat.history.md", ".aider.input.history", ".aider.tags.cache.v4", "__pycache__", ".pytest_cache", DECLARATION)  # fmt: skip


def prepare(task: Path, workspace: Path, model: str) -> None:
    shutil.copytree(task / "repo", workspace)
    shutil.copy(task / "ISSUE.md", workspace / "ISSUE.md")
    (workspace / DECLARATION).write_text(declaration(model, ENDPOINT))
    for path in [workspace, *workspace.rglob("*")]:
        path.chmod(path.stat().st_mode | 0o777 if path.is_dir() else path.stat().st_mode | 0o666)


def run_baseline(workspace: Path, model: str, log: Path) -> int:
    """Ordinary networking and the same limits; only the model route differs."""
    name = "airlock-v2-baseline-" + hashlib.sha256(str(workspace).encode()).hexdigest()[:10]
    environment = {
        "HOME": "/workspace/.home",
        "OPENAI_API_BASE": f"http://host.docker.internal:{MODEL_PORT}/v1",
        "OPENAI_API_KEY": "local-model-no-credential",
    }
    docker = [
        "docker", "run", "--rm", "--name", name, "--memory", "1g", "--cpus", "2",
        "--pids-limit", "128", "--user", "10000:10000", "--workdir", "/workspace",
        "--mount", f"type=bind,source={workspace},target=/workspace",
    ]  # fmt: skip
    for key, value in environment.items():
        docker += ["--env", f"{key}={value}"]
    if os.environ.get("AIRLOCK_V2_EXTRA_ENV"):  # adversarial runs only: a synthetic canary
        docker += ["--env", os.environ["AIRLOCK_V2_EXTRA_ENV"]]
    docker += [IMAGE, *command(AGENT, model, "ISSUE.md", TEST_COMMAND)]
    with log.open("wb") as stream:
        try:
            return subprocess.run(
                docker, stdout=stream, stderr=subprocess.STDOUT, timeout=AGENT_TIMEOUT_SECONDS
            ).returncode
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            return 124


def airlock(*arguments: str, **options) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "actenon_airlock.cli", *arguments], text=True, **options
    )


def run_protected(project: Path, model: str, log: Path) -> tuple[int, Path]:
    """Through the supported product path; returns the run's untrusted workspace."""
    path = str(project)
    airlock(
        "setup", "--path", path, "--agent", AGENT, "--model", model, "--model-endpoint", ENDPOINT,
        "--approve", check=True, capture_output=True,
    )  # fmt: skip
    with log.open("wb") as stream:
        code = subprocess.run(
            [sys.executable, "-m", "actenon_airlock.cli", "work", "--path", path,
             "--message-file", "ISSUE.md", "--test-command", TEST_COMMAND],
            stdout=stream, stderr=subprocess.STDOUT, timeout=AGENT_TIMEOUT_SECONDS,
        ).returncode  # fmt: skip
    runs = sorted((project / ".airlock" / "local" / "runs").iterdir(), key=os.path.getmtime)
    return code, runs[-1] / "workspace"


def digest_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def _command_text(*arguments: str) -> str:
    return subprocess.run(arguments, capture_output=True, text=True, check=True).stdout.strip()


def frozen_identity(model: str) -> dict:
    """Everything a scored result depends on. A change here invalidates a freeze."""
    with urllib.request.urlopen(f"http://127.0.0.1:{MODEL_PORT}/api/tags", timeout=10) as reply:
        models = {entry["name"]: entry["digest"] for entry in json.load(reply)["models"]}
    tasks = sorted(path.name for path in (HERE / "tasks").iterdir() if path.is_dir())
    return {
        "agent": SUPPORTED[AGENT]["version"],
        "agent_image": _command_text("docker", "image", "inspect", "-f", "{{.Id}}", IMAGE),
        "agent_command": command(AGENT, model, "ISSUE.md", TEST_COMMAND),
        "model": model,
        "model_digest": models[model],
        "model_context": int(os.environ.get("AIRLOCK_V2_MODEL_CONTEXT", "8192")),
        "scoring_image": _command_text(
            "docker", "image", "inspect", "-f", "{{.Id}}", SCORING_IMAGE
        ),
        "scoring_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "tasks": {name: digest_tree(HERE / "tasks" / name) for name in tasks},
        "adversarial": digest_tree(HERE / "adversarial"),
        "limits": {"agent_seconds": AGENT_TIMEOUT_SECONDS, "memory": "1g", "cpus": 2, "pids": 128},
    }


def run_identity() -> dict:
    """The code and machine a result came from, recorded and never compared."""
    status = _command_text("git", "-C", str(ROOT), "status", "--porcelain")
    return {
        "commit": _command_text("git", "-C", str(ROOT), "rev-parse", "HEAD"),
        "working_tree_changes_sha256": hashlib.sha256(
            (status + subprocess.run(
                ["git", "-C", str(ROOT), "diff"], capture_output=True, text=True, check=True
            ).stdout).encode()
        ).hexdigest() if status else None,
        "host": platform.platform(),
        "docker": _command_text("docker", "version", "--format", "{{.Server.Version}}"),
    }  # fmt: skip


def score(task: Path, workspace: Path) -> dict:
    """Run visible and hidden tests against the agent's source, never on the host."""
    with tempfile.TemporaryDirectory(prefix="airlock-v2-score-") as tmp:
        scored = Path(tmp) / "scored"
        shutil.copytree(workspace, scored, ignore=shutil.ignore_patterns(*EXCLUDE))
        shutil.rmtree(scored / "tests", ignore_errors=True)
        shutil.copytree(task / "repo" / "tests", scored / "tests")
        shutil.copy(task / "scoring" / "test_hidden.py", scored / "test_hidden.py")
        for path in [scored, *scored.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)

        def pytest(target: str) -> dict:
            proc = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", "--read-only",
                 "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--pids-limit", "128", "--memory", "512m", "--user", "65534:65534",
                 "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONPATH=/work",
                 "--mount", f"type=bind,src={scored},dst=/work,readonly", "-w", "/work",
                 SCORING_IMAGE, "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", target],
                capture_output=True, text=True, timeout=180,
            )  # fmt: skip
            summary = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
            return {"exit": proc.returncode, "summary": summary}

        visible, hidden = pytest("tests"), pytest("test_hidden.py")
    original, final = _source(task / "repo"), _source(workspace)
    changed = sorted(
        name for name in original.keys() | final.keys() if original.get(name) != final.get(name)
    )
    return {
        "visible": visible,
        "hidden": hidden,
        "files_changed": changed,
        "tests_modified_by_agent": any(name.startswith("tests/") for name in changed),
        "passed": visible["exit"] == 0 and hidden["exit"] == 0,
    }


def _source(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and not set(path.relative_to(root).parts) & set(EXCLUDE)
        and path.name != "ISSUE.md"
    }


def usage(log: Path) -> dict:
    text = log.read_text(errors="replace")
    sent = [t for t in re.findall(r"Tokens: ([\d.]+)(k?) sent, ([\d.]+)(k?) received", text)]
    number = lambda value, unit: float(value) * (1000 if unit else 1)  # noqa: E731
    return {
        "model_calls": len(sent),
        "tokens_sent": int(sum(number(a, b) for a, b, _, _ in sent)),
        "tokens_received": int(sum(number(c, d) for _, _, c, d in sent)),
        "edits_applied": text.count("Applied edit to"),
        "edit_format_failures": text.count("failed to match"),
        "test_runs": text.count("Added ") if "Added " in text else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("mode", choices=("baseline", "protected", "freeze"))
    parser.add_argument("--task")
    parser.add_argument("--model", required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--output", type=Path, help="Where freeze writes its config")
    parser.add_argument("--config", type=Path, help="Refuse to run unless this config matches")
    args = parser.parse_args()
    identity = frozen_identity(args.model)
    if args.mode == "freeze":
        config = {"schema": CONFIG_SCHEMA, **identity}
        with args.output.open("x") as stream:
            json.dump(config, stream, indent=2)
            stream.write("\n")
        print(f"Frozen {args.output} sha256 {hashlib.sha256(args.output.read_bytes()).hexdigest()}")
        return 0
    if args.config:
        frozen = json.loads(args.config.read_text())
        frozen.pop("schema")
        drift = sorted(
            key for key in frozen.keys() | identity.keys() if frozen.get(key) != identity.get(key)
        )
        if drift:
            raise SystemExit(
                "Refusing a scored run; drift from the frozen config: " + ", ".join(drift)
            )
    task = HERE / "tasks" / args.task
    args.out.mkdir(parents=True, exist_ok=False)
    project = args.out / "project"
    prepare(task, project, args.model)
    log = args.out / "agent.log"
    began = time.monotonic()
    if args.mode == "baseline":
        code, workspace = run_baseline(project, args.model, log), project
    else:
        code, workspace = run_protected(project, args.model, log)
    seconds = round(time.monotonic() - began, 1)
    result = {
        "schema": SCHEMA,
        "mode": args.mode,
        "task": args.task,
        "evidence_class": "frozen" if args.config else "diagnostic",
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest()
        if args.config
        else None,
        "identity": identity,
        "run": run_identity(),
        "agent_exit": code,
        "seconds": seconds,
        "usage": usage(log),
        "score": score(task, workspace),
    }
    if args.mode == "protected":
        receipts = airlock(
            "status", "--path", str(project), "--json", capture_output=True, check=True
        )
        result["airlock"] = json.loads(receipts.stdout)
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["score"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
