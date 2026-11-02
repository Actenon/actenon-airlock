#!/usr/bin/env python3
"""Claude Code acceptance: an unchanged agent on one scored task, baseline or protected.

    python acceptance/claude-code/run_task.py protected --task T --out DIR --rehearse
    python acceptance/claude-code/run_task.py protected --task T --out DIR --model M \
        --authorized-usd 2.00 --config CONFIG
    python acceptance/claude-code/run_task.py freeze --model M --output CONFIG

--rehearse replays a scripted endpoint, so it bills nothing and shows only that the
harness works. Without it a run is billable, and it refuses to start without an API key
and an explicit spending authorization. Both modes use the same image, command, task and
scoring. The baseline has ordinary networking and no Airlock; the protected run goes
through `airlock setup` and `airlock work`. Tasks, scoring and the sink come from
acceptance v2 unchanged. Agent output is never executed on this host.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.append(str(ROOT / "acceptance" / "v2"))

# Re-exported: attacks.py and journey.py reuse v2's frozen sink, classifier and journey.
import adversarial as v2a  # noqa: E402, F401
import flagship as v2f  # noqa: E402, F401
import harness as v2  # noqa: E402
from gateway import BaselineGateway  # noqa: E402

from actenon_airlock.agents import (  # noqa: E402
    DECLARATION,
    SUPPORTED,
    command,
    declaration,
    parse_prices,
    usd_to_micro,
)
from actenon_airlock.synthetic_anthropic import ScriptedEndpoint, text, tool  # noqa: E402

AGENT = "claude-code"
PROFILE = SUPPORTED[AGENT]
IMAGE = PROFILE["image"]
SCHEMA = "actenon-airlock/claude-code-acceptance/v1"
CONFIG_SCHEMA = "actenon-airlock/claude-code-acceptance-config/v1"
REHEARSAL_MODEL = "claude-rehearsal-model"
RUN_LIMIT_USD = "2.00"
AGENT_TIMEOUT_SECONDS = 1200
# Published first-party rates as of 2026-10-06: input, cache write, cache read, output.
# Re-check them against the pricing page before authorizing a run.
PRICES = {
    "claude-opus-5-5": "4,5,0.2,20",
    "claude-sonnet-5-5": "2,2.5,0.2,10",
    REHEARSAL_MODEL: "2,2.5,0.2,10",
}
PROGRAMME = ("run_task.py", "attacks.py", "journey.py", "claude_programme.py", "gateway.py")


def agent_command(model: str) -> list[str]:
    return command(
        AGENT,
        model,
        "ISSUE.md",
        "",
        max_output_tokens=PROFILE["max_output_tokens"],
        budget_usd=RUN_LIMIT_USD,
    )


def require_authorization(args) -> None:
    """Billable work starts only on an explicit owner decision, never by default."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise SystemExit("A live run needs ANTHROPIC_API_KEY in this supervisor's environment")
    if key.startswith("sk-ant-oat"):
        raise SystemExit("Subscription tokens cannot be used here: use a Console API key")
    if args.model not in PRICES:
        raise SystemExit(f"No reviewed prices for {args.model}")
    if args.authorized_usd is None or Decimal(args.authorized_usd) < Decimal(RUN_LIMIT_USD):
        raise SystemExit(
            f"Live runs are billable. Pass --authorized-usd of at least {RUN_LIMIT_USD} "
            "only with the owner's authorization"
        )


@dataclass
class Route:
    """How one run reaches a model. Nothing else differs between live and rehearsal."""

    kind: str
    model: str
    endpoint: str
    baseline_url: str
    closer: object

    def close(self) -> None:
        self.closer()


def open_route(args, steps: list, mode: str) -> Route:
    if args.rehearse:
        server = ScriptedEndpoint(steps)
        return Route(
            "rehearsal",
            REHEARSAL_MODEL,
            f"http://127.0.0.1:{server.port}/v1/messages",
            f"http://host.docker.internal:{server.port}",
            server.close,
        )
    require_authorization(args)
    endpoint = "https://api.anthropic.com/v1/messages"
    if mode != "baseline":
        return Route("live", args.model, endpoint, "", lambda: None)
    gateway = BaselineGateway(
        limit_microusd=usd_to_micro(RUN_LIMIT_USD), prices=parse_prices(PRICES[args.model])
    )
    url = f"http://host.docker.internal:{gateway.port}"
    return Route("live", args.model, endpoint, url, gateway.close)


def prepare(task: Path, workspace: Path, route: Route) -> None:
    shutil.copytree(task / "repo", workspace)
    shutil.copy(task / "ISSUE.md", workspace / "ISSUE.md")
    (workspace / DECLARATION).write_text(declaration(route.model, route.endpoint))
    (workspace / ".home").mkdir()
    (workspace / ".tmp").mkdir()
    open_for_agent(workspace)


def open_for_agent(workspace: Path) -> None:
    for path in [workspace, *workspace.rglob("*")]:
        path.chmod(path.stat().st_mode | 0o777 if path.is_dir() else path.stat().st_mode | 0o666)


def run_baseline(workspace: Path, route: Route, log: Path, extra_env=()) -> int:
    """Same image, limits and command. It has ordinary networking and no Airlock."""
    name = "airlock-cc-baseline-" + hashlib.sha256(str(workspace).encode()).hexdigest()[:10]
    environment = {
        "HOME": "/workspace/.home",
        "TMPDIR": "/workspace/.tmp",
        "ANTHROPIC_BASE_URL": route.baseline_url,
        # The gateway holds the real key. This container runs hostile code on purpose.
        "ANTHROPIC_API_KEY": "baseline-gateway-holds-the-key",
    }
    docker = [
        "docker", "run", "--rm", "--name", name, "--memory", "1g", "--cpus", "2",
        "--pids-limit", "128", "--user", "10000:10000", "--workdir", "/workspace",
        "--mount", f"type=bind,source={workspace},target=/workspace",
    ]  # fmt: skip
    for key, value in environment.items():
        docker += ["--env", f"{key}={value}"]
    for entry in extra_env:
        docker += ["--env", entry]
    with log.open("wb") as stream:
        try:
            return subprocess.run(
                [*docker, IMAGE, *agent_command(route.model)],
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=AGENT_TIMEOUT_SECONDS,
            ).returncode
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            return 124


def setup_arguments(project: Path, route: Route) -> list[str]:
    prices = PRICES[route.model]
    return [
        "setup", "--path", str(project), "--agent", AGENT, "--model", route.model,
        "--model-endpoint", route.endpoint, "--max-run-usd", RUN_LIMIT_USD,
        "--price-per-mtok", prices,
    ]  # fmt: skip


def run_protected(project: Path, route: Route, log: Path) -> tuple[int, Path]:
    """Through the supported product path. Returns the run's untrusted workspace."""
    v2.airlock(*setup_arguments(project, route), "--approve", check=True, capture_output=True)
    with log.open("wb") as stream:
        code = subprocess.run(
            [sys.executable, "-m", "actenon_airlock.cli", "work", "--path", str(project),
             "--message-file", "ISSUE.md"],
            stdout=stream, stderr=subprocess.STDOUT, timeout=AGENT_TIMEOUT_SECONDS,
        ).returncode  # fmt: skip
    runs = sorted((project / ".airlock/local/runs").iterdir(), key=os.path.getmtime)
    return code, runs[-1] / "workspace"


def agent_events(log: Path) -> list[dict]:
    """The agent's stream-json lines, read as untrusted data."""
    events = []
    for line in log.read_text(errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and "type" in event:
            events.append(event)
    return events


def transcript(log: Path) -> dict:
    """What the client itself reported. It is never evidence of an outside effect."""
    events = agent_events(log)
    result = next((e for e in reversed(events) if e["type"] == "result"), {})
    calls = [
        block
        for event in events
        if event["type"] == "assistant"
        for block in event.get("message", {}).get("content", [])
        if isinstance(block, dict) and block.get("type") == "tool_use"
    ]
    stops = {
        event.get("message", {}).get("stop_reason")
        for event in events
        if event["type"] == "assistant"
    }
    return {
        "client_result": result.get("subtype"),
        "turns": result.get("num_turns"),
        "client_estimated_cost_usd": result.get("total_cost_usd"),
        "usage": result.get("usage"),
        "tool_calls": dict(collections.Counter(c.get("name") for c in calls)),
        "bash_commands": [c["input"].get("command") for c in calls if c.get("name") == "Bash"],
        "model_refused": "refusal" in stops or result.get("stop_reason") == "refusal",
    }


def image_id(name: str) -> str:
    return v2._command_text("docker", "image", "inspect", "-f", "{{.Id}}", name)


def frozen_identity(model: str) -> dict:
    """Everything a scored result depends on. A change here invalidates a freeze."""
    tasks = v2.HERE / "tasks"
    lock = ROOT / "containers" / "claude-code" / "package-lock.json"
    return {
        "agent": PROFILE["version"],
        "agent_image": image_id(IMAGE),
        "agent_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "agent_command": agent_command(model),
        "contract": PROFILE["contract"],
        "anthropic_betas": list(PROFILE["anthropic_betas"]),
        "model": model,
        "price_per_mtok": PRICES[model],
        "scoring_image": image_id(v2.SCORING_IMAGE),
        "programme_sha256": {
            name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in PROGRAMME
        },
        "tasks": {
            path.name: v2.digest_tree(path) for path in sorted(tasks.iterdir()) if path.is_dir()
        },
        "adversarial": {
            "v2": v2.digest_tree(v2.HERE / "adversarial"),
            "claude_code": v2.digest_tree(HERE / "planted"),
        },
        "limits": {
            "agent_seconds": AGENT_TIMEOUT_SECONDS,
            "run_usd": RUN_LIMIT_USD,
            "memory": "1g",
            "cpus": 2,
            "pids": 128,
        },
    }


def check_frozen(args, identity: dict) -> None:
    frozen = json.loads(args.config.read_text())
    frozen.pop("schema")
    drift = sorted(k for k in frozen.keys() | identity.keys() if frozen.get(k) != identity.get(k))
    if drift:
        raise SystemExit("Refusing a scored run; drift from the frozen config: " + ", ".join(drift))


def evidence_class(args, route: Route) -> str:
    if route.kind == "rehearsal":
        return "rehearsal"
    return "frozen-live" if args.config else "diagnostic-live"


def apply_reference(task: Path) -> list:
    """Rehearsal only: replay the known fix, so later steps have a real change to handle."""
    reference = task / "scoring" / "reference"
    files = sorted(path for path in reference.rglob("*") if path.is_file())
    return [
        [
            tool(
                f"write-{index}",
                "Write",
                file_path="/workspace/" + str(path.relative_to(reference)),
                content=path.read_text(),
            )
        ]
        for index, path in enumerate(files)
    ]


def rehearsal_steps(task: Path) -> list:
    run_tests = tool("tests", "Bash", command="python -m pytest -q", description="Run tests")
    return [[run_tests], *apply_reference(task), [run_tests], [text("Finished.")]]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("mode", choices=("baseline", "protected", "freeze"))
    parser.add_argument("--task")
    parser.add_argument("--model", default="claude-opus-5-5")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--output", type=Path, help="Where freeze writes its config")
    parser.add_argument("--config", type=Path, help="Refuse to run unless this config matches")
    parser.add_argument("--rehearse", action="store_true", help="Scripted endpoint; bills nothing")
    parser.add_argument("--authorized-usd", help="Owner-authorized spend for this run")
    args = parser.parse_args()
    if args.mode == "freeze":
        config = {"schema": CONFIG_SCHEMA, **frozen_identity(args.model)}
        with args.output.open("x") as stream:
            json.dump(config, stream, indent=2)
            stream.write("\n")
        print(f"Frozen {args.output} sha256 {hashlib.sha256(args.output.read_bytes()).hexdigest()}")
        return 0
    task = v2.HERE / "tasks" / args.task
    route = open_route(args, rehearsal_steps(task), args.mode)
    try:
        identity = frozen_identity(route.model)
        if args.config:
            check_frozen(args, identity)
        args.out.mkdir(parents=True, exist_ok=False)
        project = args.out / "project"
        prepare(task, project, route)
        log = args.out / "agent.log"
        began = time.monotonic()
        if args.mode == "baseline":
            code, workspace = run_baseline(project, route, log), project
        else:
            code, workspace = run_protected(project, route, log)
        seconds = round(time.monotonic() - began, 1)
    finally:
        route.close()
    result = {
        "schema": SCHEMA,
        "mode": args.mode,
        "task": args.task,
        "evidence_class": evidence_class(args, route),
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest()
        if args.config
        else None,
        "identity": identity,
        "run": v2.run_identity(),
        "agent_exit": code,
        "seconds": seconds,
        "agent": transcript(log),
        "score": v2.score(task, workspace),
    }
    if args.mode == "protected":
        receipts = v2.airlock(
            "status", "--path", str(project), "--json", capture_output=True, check=True
        )
        result["airlock"] = json.loads(receipts.stdout)
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("mode", "task", "agent_exit", "evidence_class")}))
    print(json.dumps(result["score"]))
    return 0 if result["score"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
