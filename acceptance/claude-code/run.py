#!/usr/bin/env python3
"""Dedicated Anthropic acceptance for Claude Code on token-bucket.

Rehearsal is scripted and never scores autonomy. A live run requires --live,
--config, --authorized-usd 2 and a supervisor-only ANTHROPIC_API_KEY.
Contained compute never receives that key. Baseline networking is open;
both modes have the same agent, model contract, budget, task and independent tests.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.metadata
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "acceptance/v2"), str(ROOT / "tests"), str(ROOT / "acceptance")]
import dependency_identity  # noqa: E402
import harness as scoring  # noqa: E402
from anthropic_fixture import ScriptedProvider, stream_reply, text, tool  # noqa: E402

from actenon_airlock.agents import SUPPORTED, command  # noqa: E402
from actenon_airlock.cli import main as airlock  # noqa: E402
from actenon_airlock.common import host_environment  # noqa: E402
from actenon_airlock.credential_preflight import (  # noqa: E402
    CredentialRefused,
    authenticate_anthropic,
    supervisor_anthropic_credential,
    supervisor_scope,
)
from actenon_airlock.manifest import discover  # noqa: E402
from actenon_airlock.protected import Docker, ProtectedBroker, snapshot  # noqa: E402
from actenon_airlock.state import State  # noqa: E402
from actenon_airlock.workflow import status  # noqa: E402

AGENT = "claude-code"
MODEL = "claude-opus-5-5"
PRICES = SUPPORTED[AGENT]["default_prices"]  # "4,5,0.2,20"
BUDGET = "2"
SCHEMA = "actenon-airlock/claude-code-acceptance/v1"
ENDPOINT = "https://api.anthropic.com/v1/messages"
IMAGE = SUPPORTED[AGENT]["image"]


@contextlib.contextmanager
def capture_output(log):
    """Capture Python output and inherited Docker attachment file descriptors."""
    sys.stdout.flush()
    sys.stderr.flush()
    originals = [os.dup(fd) for fd in (1, 2)]
    try:
        for fd in (1, 2):
            os.dup2(log.fileno(), fd)
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            yield
    finally:
        log.flush()
        for fd, saved in zip((1, 2), originals):
            os.dup2(saved, fd)
            os.close(saved)


def identity(image):
    docker = Docker()
    paths = [
        Path(__file__),
        ROOT / "tests/anthropic_fixture.py",
        ROOT / "acceptance/v2/harness.py",
        ROOT / "acceptance/dependency_identity.py",
        ROOT / "containers/claude-code/package-lock.json",
    ]
    return {
        "schema": SCHEMA,
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, env=host_environment()
        ).strip(),
        "source_digest": scoring.digest_tree(ROOT / "src/actenon_airlock"),
        "python": sys.version,
        "installed_versions": dict(
            sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions())
        ),
        # Identity v2 (acceptance/dependency_identity.py): the installed dependencies must be
        # the artifacts uv.lock pins, git commits or registry wheels. The criteria are unchanged.
        "identity_version": 2,
        "dependency_identity": dependency_identity.SCHEMA,
        "candidate_dependencies": dependency_identity.identify(ROOT / "uv.lock"),
        "image": docker.image(image)["Id"],
        "model": MODEL,
        "prices": PRICES,
        "run_usd": BUDGET,
        "command": command(
            AGENT,
            MODEL,
            "ISSUE.md",
            "",
            max_output_tokens=SUPPORTED[AGENT]["max_output_tokens"],
            budget_usd=BUDGET,
        ),
        "programme": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths
        },
        "tasks": {
            p.name: scoring.digest_tree(p)
            for p in sorted((ROOT / "acceptance/v2/tasks").iterdir())
            if p.is_dir()
        },
    }


def rehearsal(task):
    """Reference solutions are used ONLY by this explicitly scripted rehearsal."""
    ref_files = sorted((task / "scoring/reference").rglob("*.py"))
    steps = [
        [tool("inspect", "Bash", command="python -m pytest -q", description="Run initial tests")]
    ]
    for i, file in enumerate(ref_files):
        rel = str(file.relative_to(task / "scoring/reference"))
        steps.append(
            [
                tool(
                    f"edit{i}",
                    "Write",
                    file_path=f"/workspace/{rel}",
                    content=file.read_text(),
                )
            ]
        )
    steps.append(
        [tool("test", "Bash", command="python -m pytest -q", description="Run verification tests")]
    )
    steps.append([text("Scripted rehearsal complete.")])
    return steps


class Gateway:
    """Acceptance-only baseline adapter. No key or trusted files enter compute.

    Uses the same reviewed inference policy. Baseline still has ordinary network
    access for controlled adversarial comparisons. A random URL authenticates this
    disposable listener; it is not a product endpoint.
    """

    def __init__(self, broker):
        self.nonce = secrets.token_urlsafe(32)
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                if self.path.endswith("/api/hello"):
                    self.send_response(200)
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                path, _, _ = self.path.partition("?")
                if path != "/" + gateway.nonce + "/v1/messages":
                    self.send_error(404)
                    return
                size = int(self.headers.get("Content-Length", "0"))
                max_bytes = SUPPORTED[AGENT]["max_input_bytes"]
                if not 0 < size <= max_bytes or self.headers.get("Transfer-Encoding"):
                    self.send_error(413)
                    return
                raw = self.rfile.read(size)
                forward_headers = {
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() in {"content-type", "anthropic-version", "anthropic-beta"}
                }
                result = broker.handle(
                    {
                        "kind": "protected-http",
                        "method": "POST",
                        "url": ENDPOINT,
                        "headers": forward_headers,
                        "body": base64.b64encode(raw).decode(),
                    }
                )
                response = result.get("response", {})
                body = (
                    base64.b64decode(response["body"])
                    if "body" in response
                    else json.dumps(
                        {
                            "type": "error",
                            "error": {
                                "type": "permission_error",
                                "message": result.get("reason", "Refused"),
                            },
                        }
                    ).encode()
                )
                self.send_response(response.get("status", 403))
                self.send_header(
                    "Content-Type",
                    response.get("headers", {}).get("content-type", "application/json"),
                )
                self.send_header("Content-Length", str(len(body)))
                for name in ("retry-after", "x-should-retry"):
                    if name in response.get("headers", {}):
                        self.send_header(name, response["headers"][name])
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://host.docker.internal:{self.server.server_port}/{self.nonce}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def baseline(project, image, log, gateway):
    work = project.parent / "baseline-workspace"
    snapshot(project, work)
    (work / ".tmp").mkdir(exist_ok=True)
    for p in [work, *work.rglob("*")]:
        p.chmod(0o777 if p.is_dir() else 0o666)
    name = "airlock-claude-baseline-" + secrets.token_hex(6)
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=64m,mode=1777",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--user",
        "10000:10000",
        "--workdir",
        "/workspace",
        "--add-host",
        "host.docker.internal:host-gateway",
        "--mount",
        f"type=bind,source={work},target=/workspace",
        "--env",
        "HOME=/tmp/home",
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "ANTHROPIC_BASE_URL=" + gateway.url,
        "--env",
        "ANTHROPIC_API_KEY=baseline-no-standing-credential",
        image,
        *command(
            AGENT,
            MODEL,
            "ISSUE.md",
            "",
            max_output_tokens=SUPPORTED[AGENT]["max_output_tokens"],
            budget_usd=BUDGET,
        ),
    ]
    try:
        return (
            subprocess.run(
                argv, stdout=log, stderr=subprocess.STDOUT, timeout=1200, env=host_environment()
            ).returncode,
            work,
        )
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, env=host_environment())


def git_diff(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "diff", "HEAD"], cwd=repo, text=True, env=host_environment()
        )
    except Exception:
        return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "baseline", "protected", "preflight"))
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--task",
        choices=tuple(p.name for p in (ROOT / "acceptance/v2/tasks").iterdir() if p.is_dir()),
        default="token-bucket",
    )
    parser.add_argument("--config", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--authorized-usd", choices=(BUDGET, "2.00"))
    parser.add_argument(
        "--credential-file",
        type=Path,
        help="Owner-only one-line file holding the supervisor key (instead of ANTHROPIC_API_KEY)",
    )
    args = parser.parse_args()
    if args.mode != "preflight" and args.out is None:
        raise SystemExit("--out is required")
    supervised = args.live or args.mode == "preflight"
    if args.credential_file is not None and not supervised:
        raise SystemExit("--credential-file is only for --live or preflight")

    # The key lives in this variable, NOT in os.environ, so no host subprocess
    # (git, Docker client, scoring) can inherit it. Only broker construction
    # sees it, through supervisor_scope below.
    key = "scripted-anthropic-no-real-credential"
    if supervised:
        try:
            key = supervisor_anthropic_credential(
                os.environ.get("ANTHROPIC_API_KEY"), args.credential_file
            )
        except CredentialRefused as exc:
            raise SystemExit(f"Supervisor credential refused: {exc}") from None
    os.environ.pop("ANTHROPIC_API_KEY", None)
    os.environ.pop("OPENAI_API_KEY", None)

    frozen = identity(args.image)
    preflight = None
    if supervised:
        if not args.config or json.loads(args.config.read_text()) != frozen:
            raise SystemExit("Frozen configuration drift; refusing credential pre-flight")
        if args.live and args.authorized_usd not in (BUDGET, "2.00"):
            raise SystemExit("Live inference requires explicit owner-authorized $2")
        preflight = authenticate_anthropic(key, MODEL)
        if preflight["outcome"] != "authenticated":
            detail = ", ".join(
                str(preflight[k])
                for k in ("http_status", "outcome", "provider_error_code")
                if preflight.get(k) is not None
            )
            raise SystemExit(
                f"Supervisor credential pre-flight failed ({detail}); no inference was dispatched"
            )
        if args.mode == "preflight":
            print(
                json.dumps(
                    {"credential_preflight": preflight, "source_commit": frozen["source_commit"]}
                )
            )
            return 0
    if args.mode == "freeze":
        with args.out.open("x") as file:
            json.dump(frozen, file, indent=2)
            file.write("\n")
        return 0
    if args.config and json.loads(args.config.read_text()) != frozen:
        raise SystemExit("Frozen configuration drift; refusing acceptance")
    if args.live and (not args.config or args.authorized_usd not in (BUDGET, "2.00") or not key):
        raise SystemExit(
            "Live inference requires frozen config, explicit owner-authorized $2, and supervisor API key"
        )

    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    task = ROOT / "acceptance/v2/tasks" / args.task
    project = args.out / "project"
    shutil.copytree(task / "repo", project)
    shutil.copyfile(task / "ISSUE.md", project / "ISSUE.md")

    assert (
        airlock(
            [
                "setup",
                "--path",
                str(project),
                "--agent",
                AGENT,
                "--model",
                MODEL,
                "--approve",
                "--max-run-usd",
                BUDGET,
                "--price-per-mtok",
                PRICES,
            ]
        )
        == 0
    )

    steps = rehearsal(task) if not args.live else None
    scripted = ScriptedProvider(steps) if steps is not None else None
    original = ProtectedBroker.__init__

    def initialize(self, *a, **kw):
        with supervisor_scope("ANTHROPIC_API_KEY", key):
            original(self, *a, **kw)
        if scripted:
            self.http.close()

            def fixture(request):
                response = scripted(request)
                content = (
                    response.content.replace(b"claude-test-model", MODEL.encode())
                    if isinstance(response, httpx.Response)
                    else stream_reply(response, model=MODEL).content
                )
                return httpx.Response(
                    200 if not isinstance(response, httpx.Response) else response.status_code,
                    headers={
                        "content-type": "text/event-stream"
                        if not isinstance(response, httpx.Response)
                        else response.headers.get("content-type", "text/event-stream")
                    },
                    content=content,
                )

            self.http = httpx.Client(transport=httpx.MockTransport(fixture))

    started = time.monotonic()
    with (
        patch.object(ProtectedBroker, "__init__", initialize),
        (args.out / "agent.log").open("w") as log,
    ):
        if args.mode == "protected":
            with capture_output(log):
                code = airlock(
                    [
                        "work",
                        "--path",
                        str(project),
                        "--message-file",
                        "ISSUE.md",
                        "--image",
                        args.image,
                    ]
                )
            work = (
                max((project / ".airlock/local/runs").iterdir(), key=lambda p: p.stat().st_mtime)
                / "workspace"
            )
        else:
            state = State(project)
            broker = ProtectedBroker(
                state, discover(project), state.approved()["credential_bindings"]
            )
            gateway = Gateway(broker)
            try:
                code, work = baseline(project, args.image, log, gateway)
            finally:
                gateway.close()
                broker.close()

    scoring.SCORING_IMAGE = args.image
    score_result = scoring.score(task, work)
    airlock_state = status(State(project))
    patch_text = git_diff(work) if (work / ".git").exists() else ""
    passed = code == 0 and score_result["passed"] and not score_result["tests_modified_by_agent"]
    runner_exit = 0 if passed else 1

    result = {
        "schema": SCHEMA,
        "evidence_class": "frozen-live" if args.live else "scripted-rehearsal-NOT-autonomy",
        "mode": args.mode,
        "task": args.task,
        "model": MODEL,
        "identity": frozen,
        "agent_exit": code,
        "runner_exit": runner_exit,
        "seconds": round(time.monotonic() - started, 3),
        "score": score_result,
        "airlock": airlock_state,
        "inference": {
            "dispatched": airlock_state["inference"]["dispatched"],
            "confirmed": airlock_state["inference"]["confirmed"],
            "unconfirmed": airlock_state["inference"]["unconfirmed"],
            "retries_held": airlock_state["inference"]["retries_held"],
            "declined": airlock_state["model_spend"]["declined_calls"],
        },
        "accounting": {
            "estimated_microusd": airlock_state["model_spend"]["estimated_microusd"],
            "budget_microusd": int(Decimal(BUDGET) * 1_000_000),
            "prices": PRICES,
        },
        "evidence_integrity": {
            "integrity_ok": airlock_state["integrity_ok"],
            "refused": airlock_state["refused"],
            "unresolved_effects": len(airlock_state.get("unresolved_effects", [])),
        },
        "actual_paid_inference": args.live,
        "credential_preflight": preflight,
        "source_patch": patch_text,
    }
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    assert (
        airlock(
            ["checkpoint", "--path", str(project), "--output", str(args.out / "checkpoint.json")]
        )
        == 0
    )
    shutil.copyfile(project / ".airlock/public-key.json", args.out / "public-key.json")
    shutil.copyfile(project / ".airlock/local/receipts.jsonl", args.out / "receipts.jsonl")
    print(
        json.dumps(
            {
                "score": result["score"],
                "agent_exit": code,
                "runner_exit": runner_exit,
                "evidence_class": result["evidence_class"],
                "inference": result["inference"],
            }
        )
    )
    return runner_exit


if __name__ == "__main__":
    raise SystemExit(main())
