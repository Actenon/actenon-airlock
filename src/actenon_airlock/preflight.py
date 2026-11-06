"""Plain-English checks that run before anything slow, costly or consequential starts.

Each problem says what is wrong, what state things are in, the shortest supported fix,
the command to retry and where to read more. These checks only decide what to *say*.
The security checks in ``protected.Docker.verify_engine`` still run afterwards, unchanged,
and still refuse anything they refuse today.

Docker's own error text is never printed: daemon diagnostics can carry endpoints,
user names or other host details, so it is only matched against known patterns.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from .common import host_environment

# The same profiles protected.Docker.verify_engine accepts.
SECCOMP = {"name=seccomp,profile=builtin", "name=seccomp,profile=default"}
REPOSITORY = "https://github.com/Actenon/actenon-airlock"


def installed_commit() -> str | None:
    """The exact commit pip or pipx installed Airlock from, when it was installed from Git."""
    import importlib.metadata

    try:
        text = importlib.metadata.distribution("actenon-airlock").read_text("direct_url.json")
        commit = (json.loads(text or "{}").get("vcs_info") or {}).get("commit_id")
    except (importlib.metadata.PackageNotFoundError, ValueError, AttributeError):
        return None
    return commit if isinstance(commit, str) and len(commit) == 40 else None


def help_link(anchor: str) -> str:
    """Troubleshooting for the version that is installed, not whatever main says today."""
    return f"{REPOSITORY}/blob/{installed_commit() or 'main'}/docs/troubleshooting.md#{anchor}"


@dataclass(frozen=True)
class Problem:
    category: str
    what: str
    fix: list[str] = field(default_factory=list)
    retry: str = ""
    anchor: str = ""
    safe: str = "Nothing ran and nothing was changed."

    def render(self) -> str:
        lines = [f"Airlock cannot start: {self.what}", "", self.safe]
        if self.fix:
            lines += ["", "To fix it:"] + [f"  {step}" for step in self.fix]
        if self.retry:
            lines += ["", "Then run again:", f"  {self.retry}"]
        lines += ["", f"[{self.category}] More help: {help_link(self.anchor or 'docker')}"]
        return "\n".join(lines)


def _mac() -> bool:
    return sys.platform == "darwin"


def _start_docker() -> list[str]:
    if _mac():
        return [
            "open -a Docker",
            "Wait until Docker Desktop says it is running (about 30 seconds).",
        ]
    return ["sudo systemctl start docker", "(or start Docker Desktop, if that is what you use)"]


def docker_problem(retry: str, *, timeout: float = 20) -> Problem | None:
    """None when a local Linux Docker engine answers; otherwise what to tell the person."""
    binary = shutil.which("docker")
    if not binary:
        install = (
            ["Install Docker Desktop: https://docs.docker.com/desktop/setup/install/mac-install/",
             "Open it once so it finishes setting up."]
            if _mac()
            else ["Install Docker Engine: https://docs.docker.com/engine/install/"]
        )  # fmt: skip
        return Problem(
            "DOCKER_NOT_INSTALLED",
            "Docker is not installed (no `docker` command on your PATH).\n"
            "Airlock runs the agent inside a Docker container, so it needs Docker.",
            install,
            retry,
            "docker-is-not-installed",
        )
    environment = host_environment()
    try:
        context = subprocess.run(
            [binary, "context", "inspect"], capture_output=True, text=True, timeout=10,
            env=environment, check=False,
        )  # fmt: skip
        endpoint = json.loads(context.stdout)[0]["Endpoints"]["docker"]["Host"]
        if not environment.get("DOCKER_CONTEXT"):
            endpoint = environment.get("DOCKER_HOST") or endpoint
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, IndexError, TypeError):
        endpoint = environment.get("DOCKER_HOST") or "unix://"
    if not str(endpoint).startswith("unix://"):
        return Problem(
            "DOCKER_REMOTE_ENGINE",
            "Docker is set to use an engine on another machine.\n"
            "Airlock only uses a Docker engine running on this machine.",
            ["unset DOCKER_HOST", "docker context use default"],
            retry,
            "docker-points-at-another-machine",
        )
    try:
        info = subprocess.run(
            [binary, "info", "--format", "{{json .}}"], capture_output=True, text=True,
            timeout=timeout, env=environment, check=False,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        return Problem(
            "DOCKER_NOT_RESPONDING",
            f"Docker did not answer within {int(timeout)} seconds.\n"
            "If Docker Desktop is still starting, wait until it says it is running.",
            _start_docker(),
            retry,
            "docker-is-not-running",
        )
    except OSError:
        return Problem(
            "DOCKER_NOT_RUNNING", "the `docker` command could not be run.", _start_docker(),
            retry, "docker-is-not-running",
        )  # fmt: skip
    if info.returncode:
        text = (info.stderr or "").lower()
        if "permission denied" in text:
            return Problem(
                "DOCKER_PERMISSION_DENIED",
                "Docker is running, but your user is not allowed to use it.",
                [
                    "Follow Docker's guide for your setup (rootless Docker, or the docker group):",
                    "https://docs.docker.com/engine/install/linux-postinstall/",
                    "Note: membership of the docker group is equivalent to root on this machine.",
                ],
                retry,
                "docker-permission-denied",
            )
        return Problem(
            "DOCKER_NOT_RUNNING",
            "Docker is installed but not running.",
            _start_docker(),
            retry,
            "docker-is-not-running",
        )
    try:
        details = json.loads(info.stdout)
    except ValueError:
        details = {}
    if details.get("OSType") != "linux":
        return Problem(
            "DOCKER_NOT_LINUX",
            "Docker is running, but not with Linux containers.",
            ["Switch Docker to Linux containers, then try again."],
            retry,
            "docker-is-not-using-linux-containers",
        )
    if not set(details.get("SecurityOptions") or []) & SECCOMP:
        return Problem(
            "DOCKER_NO_SECCOMP",
            "Docker is running without its seccomp protection, which Airlock requires.",
            [
                "Use a Docker engine with seccomp enabled (Docker Desktop and Docker Engine have it)."
            ],
            retry,
            "docker-has-no-seccomp",
        )
    return None


def require_docker(retry: str) -> bool:
    """Print the problem and return False, or return True when Docker is ready."""
    problem = docker_problem(retry)
    if problem:
        print(problem.render(), file=sys.stderr)
        return False
    return True
