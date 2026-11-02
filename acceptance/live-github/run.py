#!/usr/bin/env python3
"""One real, approved GitHub write, proved by reading it back. Owner-run.

    GITHUB_TOKEN=... python acceptance/live-github/run.py --repo OWNER/REPO --out DIR \
        --confirm-live-write

The change comes from a fixed script in Protected Mode, because this measures the path to the
provider, not a model. It refuses a public repository or one with real history. --synthetic
runs the same steps against the synthetic provider, with no account and no network.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import httpx

from actenon_airlock.synthetic_github import TOKEN, create_provider

BRANCH = "review"
MAX_COMMITS = 5
SCHEMA = "actenon-airlock/live-github-test/v1"
IMAGE = "actenon-airlock-compute:dev"
UNUSED_MODEL = "http://127.0.0.1:9/v1/chat/completions"  # The fixed script calls no model.
FIX = (
    "import pathlib\n"
    "source = pathlib.Path('calculator.py')\n"
    "source.write_text(source.read_text().replace('a - b', 'a + b'))\n"
)


def refusal(repository: dict, commits: int) -> str | None:
    """Why this repository must not take the write. A real project never should."""
    if not repository.get("private"):
        return "the repository is public"
    if repository.get("archived"):
        return "the repository is archived"
    if commits > MAX_COMMITS:
        return f"it has {commits} commits on {BRANCH}, so it does not look disposable"
    return None


class Real:
    """Read-only facts, on a client separate from anything Airlock uses."""

    def __init__(self, full_name: str, token: str):
        self.full_name = full_name
        self.http = httpx.Client(
            base_url="https://api.github.com",
            headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"},
        )

    def get(self, path: str, **params):
        reply = self.http.get(f"/repos/{self.full_name}{path}", params=params)
        reply.raise_for_status()
        return reply.json()

    def facts(self) -> dict:
        repository, head = self.get(""), self.get(f"/commits/{BRANCH}")["sha"]
        return {
            "repository": repository,
            "head": head,
            "commits": len(self.get("/commits", sha=BRANCH, per_page=100)),
        }

    def file_bytes(self, path: str) -> bytes | None:
        reply = self.http.get(f"/repos/{self.full_name}/contents/{path}", params={"ref": BRANCH})
        if reply.status_code == 404:
            return None
        reply.raise_for_status()
        return base64.b64decode(reply.json()["content"])


class Synthetic:
    """The same questions, read directly from the synthetic provider's own file."""

    def __init__(self, path: Path):
        self.path = path

    def world(self) -> dict:
        return json.loads(self.path.read_text())

    def facts(self) -> dict:
        world = self.world()
        return {
            "repository": {**world["repository"], "private": True},
            "head": world["head"],
            "commits": len(world["commits"]),
        }

    def file_bytes(self, path: str) -> bytes | None:
        entry = self.world()["files"].get(path)
        return base64.b64decode(entry["content"]) if entry else None


class Steps:
    def __init__(self, project: Path, seam: list[str], key: Path):
        self.project, self.seam, self.key = project, seam, key
        self.transcript: list[dict] = []

    def airlock(self, *arguments, expect=(0,)) -> str:
        arguments = [str(argument) for argument in arguments]
        done = subprocess.run(
            [sys.executable, "-m", "actenon_airlock.cli", *arguments],
            capture_output=True, text=True, timeout=300,
        )  # fmt: skip
        self.transcript.append(
            {
                "command": arguments,
                "exit": done.returncode,
                "output": (done.stdout + done.stderr)[-2000:],
            }
        )
        if done.returncode not in expect:
            raise SystemExit(f"{arguments[0]} failed with exit {done.returncode}: {done.stderr}")
        return done.stdout

    def here(self, command: str, *arguments, expect=(0,)) -> str:
        return self.airlock(command, "--path", self.project, *arguments, expect=expect)

    def publish(self, candidate: str, expect=(0, 3)) -> dict:
        return json.loads(
            self.here("publish", "--json", "--candidate", candidate, *self.seam, expect=expect)
        )


def candidate(steps: Steps, out: Path) -> str:
    """A real captured, tested change from a real protected run."""
    project = steps.project
    project.mkdir()
    (project / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    (project / "fix.py").write_text(FIX)
    steps.here(
        "setup", "--agent", "aider", "--model", "unused", "--model-endpoint", UNUSED_MODEL,
        "--approve",
    )  # fmt: skip
    steps.here("run", "--protected", "--image", IMAGE, "--", "python", "fix.py")
    sha256 = json.loads(steps.here("capture", "--json"))["candidate_sha256"]
    tests = out / "trusted-tests"
    tests.mkdir()
    (tests / "test_add.py").write_text(
        "from calculator import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"
    )
    steps.here("verify-candidate", "--candidate", sha256, "--tests", tests)
    return sha256


def journey(args, observer, seam: list[str]) -> dict:
    facts = observer.facts()
    reason = refusal(facts["repository"], facts["commits"])
    if reason:
        raise SystemExit(f"Refusing this repository: {reason}")
    args.out.mkdir(parents=True)
    key = args.out / "operator.key"
    steps = Steps(args.out / "project", seam, key)
    sha256 = candidate(steps, args.out)
    path = f"patches/airlock-live-test-{sha256[:12]}.patch"
    before = observer.file_bytes(path)
    profile = args.out / "reviewed-create.json"
    owner, name = args.repo.split("/")
    facts_flags = (
        seam
        if seam
        else [
            "--repo-id", facts["repository"]["id"], "--repo-node-id", facts["repository"]["node_id"],
            "--owner", owner, "--repo", name, "--branch", BRANCH, "--parent", facts["head"],
        ]
    )  # fmt: skip
    steps.here(
        "review-candidate", "--candidate", sha256, "--output", profile, "--path-in-repo", path,
        "--message", "Airlock live test: one exact approved file", *facts_flags,
    )  # fmt: skip
    steps.here(
        "init", "--approve", "--github-create", profile, "--reconciler-key", key,
        "--credential", "GITHUB_TOKEN=https://api.github.com",
    )  # fmt: skip
    published = steps.publish(sha256)
    steps.airlock(
        "reconcile", "--path", steps.project, published["effect_id"], "--github-readback",
        "--operator-key", key, *seam,
    )  # fmt: skip
    retry = steps.publish(sha256)
    after = observer.facts()
    patch = (steps.project / ".airlock/local/candidates" / sha256 / "candidate.patch").read_bytes()
    status = json.loads(steps.here("status", "--json"))
    created = observer.file_bytes(path)
    token = os.environ["GITHUB_TOKEN"].encode()
    scanned = [p for p in (steps.project / ".airlock").rglob("*") if p.is_file()]
    checks = {
        "file_was_absent_before": before is None,
        "dispatched_unconfirmed": published["status"] == "DISPATCHED_UNCONFIRMED",
        "readback_confirmed": status["independently_observed"].get("COMMITTED") == 1,
        "no_unresolved_effects": not status["unresolved_effects"],
        "exact_bytes_at_provider": created == patch,
        "retry_refused": retry["status"] != "DISPATCHED_UNCONFIRMED",
        "exactly_one_new_commit": after["commits"] == facts["commits"] + 1,
        "token_absent_from_airlock_state": not any(token in p.read_bytes() for p in scanned),
        "token_absent_from_transcript": token.decode() not in json.dumps(steps.transcript),
    }
    return {
        "schema": SCHEMA,
        "evidence_class": "synthetic" if seam else "live",
        "repository": args.repo,
        "branch": BRANCH,
        "path": path,
        "candidate_sha256": sha256,
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "provider_bytes_sha256": hashlib.sha256(created).hexdigest() if created else None,
        "head_before": facts["head"],
        "head_after": after["head"],
        "effect_id": published["effect_id"],
        "checks": checks,
        "passed": all(checks.values()),
        "transcript": steps.transcript,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", default="acme/disposable", help="OWNER/REPO, private, disposable")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--confirm-live-write", action="store_true")
    parser.add_argument("--synthetic", action="store_true", help="No account and no network")
    args = parser.parse_args()
    if args.synthetic:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        provider = args.out.with_suffix(".provider.json")
        create_provider(provider)
        os.environ["GITHUB_TOKEN"] = TOKEN
        observer, seam = Synthetic(provider), ["--synthetic-provider", str(provider)]
    else:
        if not args.confirm_live_write:
            raise SystemExit("This writes to GitHub. Pass --confirm-live-write to go ahead")
        if not os.environ.get("GITHUB_TOKEN"):
            raise SystemExit("Set GITHUB_TOKEN to a token limited to this one repository")
        observer, seam = Real(args.repo, os.environ["GITHUB_TOKEN"]), []
    try:
        result = journey(args, observer, seam)
    except httpx.HTTPStatusError as error:
        status = error.response.status_code
        raise SystemExit(f"GitHub answered {status}. Check the repository, {BRANCH} and the token")
    (args.out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    public = args.out / "evidence"
    public.mkdir()
    state = args.out / "project" / ".airlock"
    shutil.copy(state / "local" / "receipts.jsonl", public / "receipts.jsonl")
    shutil.copy(state / "public-key.json", public / "public-key.json")
    for name, passed in result["checks"].items():
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
    print(f"\n{'PASSED' if result['passed'] else 'FAILED'} ({result['evidence_class']})")
    print(f"Evidence: {args.out / 'summary.json'} and {public}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
