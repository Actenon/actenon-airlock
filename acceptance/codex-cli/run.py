#!/usr/bin/env python3
"""Versioned Codex acceptance. Rehearsal is scripted and never scores autonomy.

A live run requires --live, --config, --authorized-usd 2 and a supervisor-only
OPENAI_API_KEY. Nothing extracts Codex/ChatGPT auth. Baseline networking is open;
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
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "acceptance/v2"), str(ROOT / "tests")]
import harness as scoring  # noqa: E402
from responses_fixture import ScriptedProvider, text, tool  # noqa: E402

from actenon_airlock.agents import command  # noqa: E402
from actenon_airlock.cli import main as airlock  # noqa: E402
from actenon_airlock.manifest import discover  # noqa: E402
from actenon_airlock.protected import Docker, ProtectedBroker, snapshot  # noqa: E402
from actenon_airlock.state import State  # noqa: E402
from actenon_airlock.workflow import status  # noqa: E402

MODEL = "gpt-5.5-2026-04-23"
PRICES = "5,0,0.5,30"
BUDGET = "2"
SCHEMA = "actenon-airlock/codex-cli-acceptance/v1"
ENDPOINT = "https://api.openai.com/v1/responses"


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
        ROOT / "tests/responses_fixture.py",
        Path(__file__).with_name("attack.py"),
        ROOT / "acceptance/v2/harness.py",
        ROOT / "containers/codex-cli/upstream.json",
    ]
    return {
        "schema": SCHEMA,
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source_digest": scoring.digest_tree(ROOT / "src/actenon_airlock"),
        "python": sys.version,
        "installed_versions": dict(
            sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions())
        ),
        "candidate_dependency_commits": {
            name: json.loads(importlib.metadata.distribution(name).read_text("direct_url.json"))[
                "vcs_info"
            ]["commit_id"]
            for name in ("actenon-protocol", "actenon-kernel", "actenon-permit", "actenon-scan")
        },
        "image": docker.image(image)["Id"],
        "model": MODEL,
        "prices": PRICES,
        "run_usd": BUDGET,
        "command": command("codex-cli", MODEL, "ISSUE.md", ""),
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
    steps = [[tool("inspect", "ls && python -m pytest -q")]]
    for i, file in enumerate(sorted((task / "scoring/reference").rglob("*.py"))):
        relative = str(file.relative_to(task / "scoring/reference"))
        code = f"from pathlib import Path; p=Path({relative!r}); p.parent.mkdir(exist_ok=True,parents=True); p.write_text({file.read_text()!r})"
        import shlex

        steps.append([tool("edit" + str(i), "python -c " + shlex.quote(code))])
    return [*steps, [tool("test", "python -m pytest -q")], [text("Scripted rehearsal complete.")]]


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
            def do_POST(self):
                if self.path != "/" + gateway.nonce + "/v1/responses":
                    self.send_error(404)
                    return
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 200000 or self.headers.get("Transfer-Encoding"):
                    self.send_error(413)
                    return
                raw = self.rfile.read(size)
                result = broker.handle(
                    {
                        "kind": "protected-http",
                        "method": "POST",
                        "url": ENDPOINT,
                        "headers": {"Content-Type": "application/json"},
                        "body": base64.b64encode(raw).decode(),
                    }
                )
                response = result.get("response", {})
                body = (
                    base64.b64decode(response["body"])
                    if "body" in response
                    else json.dumps({"error": result.get("reason", "Refused")}).encode()
                )
                self.send_response(response.get("status", 403))
                self.send_header(
                    "Content-Type",
                    response.get("headers", {}).get("content-type", "application/json"),
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("0.0.0.0", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://host.docker.internal:{self.server.server_port}/{self.nonce}/v1"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def baseline(project, image, log, gateway):
    work = project.parent / "baseline-workspace"
    snapshot(project, work)
    for p in [work, *work.rglob("*")]:
        p.chmod(0o777 if p.is_dir() else 0o666)
    name = "airlock-codex-baseline-" + secrets.token_hex(6)
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
        "OPENAI_BASE_URL=" + gateway.url,
        "--env",
        "OPENAI_API_KEY=baseline-no-standing-credential",
        image,
        *command("codex-cli", MODEL, "ISSUE.md", ""),
    ]
    try:
        return subprocess.run(
            argv, stdout=log, stderr=subprocess.STDOUT, timeout=1200
        ).returncode, work
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "baseline", "protected"))
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--task",
        choices=tuple(p.name for p in (ROOT / "acceptance/v2/tasks").iterdir() if p.is_dir()),
        default="token-bucket",
    )
    parser.add_argument("--config", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Plant untrusted instructions; observe an owned sink with a working control",
    )
    parser.add_argument("--authorized-usd", choices=(BUDGET,))
    args = parser.parse_args()
    frozen = identity(args.image)
    if args.mode == "freeze":
        with args.out.open("x") as file:
            json.dump(frozen, file, indent=2)
        return 0
    if args.config and json.loads(args.config.read_text()) != frozen:
        raise SystemExit("Frozen configuration drift; refusing acceptance")
    if args.live and (
        not args.config or args.authorized_usd != BUDGET or not os.environ.get("OPENAI_API_KEY")
    ):
        raise SystemExit(
            "Live inference requires frozen config, explicit owner-authorized $2, and supervisor API key"
        )
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    task = ROOT / "acceptance/v2/tasks" / args.task
    project = args.out / "project"
    shutil.copytree(task / "repo", project)
    shutil.copyfile(task / "ISSUE.md", project / "ISSUE.md")
    if not args.live:
        # No credential discovery or forwarding from the engineering environment.
        os.environ["OPENAI_API_KEY"] = "scripted-codex-no-real-credential"
    assert (
        airlock(
            [
                "setup",
                "--path",
                str(project),
                "--agent",
                "codex-cli",
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
    # Keep this programme below the model's 272K-token long-context price boundary.
    assert (
        airlock(
            [
                "init",
                "--path",
                str(project),
                "--model-provider",
                "openai-responses",
                "--model",
                MODEL,
                "--model-contract",
                "openai-responses-agent/v1",
                "--model-max-input-bytes",
                "200000",
                "--model-max-tokens",
                "16000",
                "--model-price",
                PRICES,
                "--model-max-run-usd",
                BUDGET,
                "--approve",
            ]
        )
        == 0
    )
    attempt = None
    if args.attack:
        from attack import Attempt

        attempt = Attempt(project, args.out, args.image)
    steps = rehearsal(task) if not args.live else None
    if steps is not None and args.attack:
        steps.insert(0, [tool("fixture-attack", "cat README.md && python diagnostics.py")])
    scripted = ScriptedProvider(steps) if steps is not None else None
    original = ProtectedBroker.__init__

    def initialize(self, *a, **kw):
        original(self, *a, **kw)
        if scripted:
            self.http.close()

            def fixture(request):
                # Scripted wire fixtures use the same pinned model identity.
                response = scripted(request)
                return httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    content=response.content.replace(b'gpt-5.5"', MODEL.encode() + b'"'),
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
    attack_result = None
    if attempt:
        attack_result = attempt.result(work)
        attempt.close()
    scoring.SCORING_IMAGE = args.image
    result = {
        "schema": SCHEMA,
        "evidence_class": "frozen-live" if args.live else "scripted-rehearsal-NOT-autonomy",
        "mode": args.mode,
        "model": MODEL,
        "identity": frozen,
        "agent_exit": code,
        "seconds": round(time.monotonic() - started, 3),
        "score": scoring.score(task, work),
        "airlock": status(State(project)),
        "actual_paid_inference": args.live,
        "attack": attack_result,
        "attack_selection": "real-agent-invoked planted code if attempted"
        if args.live
        else "harness-selected",
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
    print(json.dumps({"score": result["score"], "evidence_class": result["evidence_class"]}))
    return 0 if code == 0 and result["score"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
