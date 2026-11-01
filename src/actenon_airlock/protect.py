"""One command from a task to a reviewed change: airlock protect "Fix the failing test".

This only sequences the guided path: setup, work, capture and verify-candidate. It adds
no authority. The signed approval is still what every dispatch is checked against, a
person still gives it, and the project is not touched: the result is a patch to review.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

from .agents import SUPPORTED, TASK_FILE, require_supported
from .common import AirlockError
from .model_constraints import DEFAULT_ENDPOINTS
from .protected import DEFAULT_IMAGE, Docker, availability
from .state import State

DEFAULT_MAX_RUN_USD = "2.00"
FINISHED = {0, 3, 4}  # Agent exit, something refused, or an unresolved call.


def choose_agent(requested: str | None) -> str:
    """The agent you asked for, or the one whose model key is in this shell."""
    if requested:
        return requested
    ready = [
        name
        for name, profile in SUPPORTED.items()
        if profile.get("credential") and os.environ.get(profile["credential"])
    ]
    if len(ready) == 1:
        return ready[0]
    keys = " or ".join(p["credential"] for p in SUPPORTED.values() if p.get("credential"))
    if ready:
        raise AirlockError("Both model keys are set. Choose one with --agent")
    raise AirlockError(f"Set {keys} in this shell, or choose an agent with --agent")


def image_context() -> Path:
    """Where the image definitions are, in an installed package or a source checkout."""
    for root in (Path(sys.prefix) / "share" / "actenon-airlock", Path(__file__).parents[2]):
        if (root / "containers" / "Dockerfile.compute").is_file():
            return root
    raise AirlockError("The agent image definitions are missing from this installation")


def ensure_image(image: str, dockerfile: str | None = None) -> None:
    """Build a pinned image on first use. Each build is pinned by digest or lockfile."""
    engine = availability(image)
    if engine["available"]:
        return
    docker = Docker()
    docker.verify_engine()  # A stopped Docker is the likely cause, so report that first.
    if not dockerfile and image != DEFAULT_IMAGE:
        raise AirlockError(f"Image not available: {image}. {engine['reason']}")
    context = image_context()
    print("First run: building the sealed image. This takes a few minutes.", flush=True)
    for name, tag in (("Dockerfile.compute", DEFAULT_IMAGE), (dockerfile, image)):
        if not name:
            continue
        built = subprocess.run(
            [docker.binary, "build", "-q", "-f", str(context / "containers" / name)]
            + ["-t", tag, str(context)],
            env=docker.environment,
        )
        if built.returncode:
            raise AirlockError(f"Building {tag} failed")


def _approved(state: State, config: dict) -> bool:
    """Already signed for exactly this run. Changed code stays blocked at dispatch regardless."""
    path = state.path / "agent.json"
    if not (state.path / "approved.json").exists() or not path.exists():
        return False
    recorded = json.loads(path.read_text())
    return all(recorded.get(key) == value for key, value in config.items())


def _ask() -> bool:
    if not sys.stdin.isatty():
        raise AirlockError("Approval needs a person. Rerun in a terminal, or review and --approve")
    return input("Approve this for this project? [y/N] ").strip().lower() in {"y", "yes"}


def _new_run(state: State, before: set[Path]) -> Path | None:
    runs = state.local / "runs"
    finished = [p for p in runs.iterdir() if p not in before and (p / "result.json").is_file()]
    return max(finished, key=lambda p: (p / "result.json").stat().st_mtime, default=None)


def _usd(microusd: int) -> str:
    return f"${Decimal(microusd) / 1_000_000:.2f}"


def report(manifest, verdict, activity, patch, *, agent_exit, spend_limit, root) -> None:
    """What happened in this run, in the order a person cares about."""
    blocked, calls = activity["refused"], activity["inference"]
    print("\nRESULT")
    print(f"  Agent     finished, exit {agent_exit}")
    if manifest:
        print(f"  Changed   {len(manifest['changes'])} file(s)")
        for change in manifest["changes"]:
            print(f"              {change['status']:<9}{change['path']}")
    else:
        print("  Changed   nothing")
    print(f"  Tests     {verdict or 'not run. Pass --tests DIR to check it with your own tests'}")
    print(f"  Blocked   {blocked} attempt(s)")
    for reason in activity["refusal_reasons"]:
        print(f"              {reason}")
    spent = _usd(activity["model_spend"]["estimated_microusd"])
    print(f"  Model     {calls['dispatched']} call(s), about {spent} of {spend_limit}")
    state = "OK" if activity["integrity_ok"] else "FAILED"
    print(f"  Evidence  {activity['receipts']} signed receipt(s), integrity {state}")
    if activity["unresolved_effects"]:
        print(f"  Uncertain {len(activity['unresolved_effects'])} call(s) with no confirmed answer")
    if manifest:
        relative = patch.relative_to(root)
        print("\nYour project has not been changed. Read the patch, then take it if you want it:")
        print(f"  git apply {relative}")


def protect(args, root: Path, run) -> int:
    from .workflow import TESTS_PASSED, capture_candidate, status, verify_candidate

    agent = choose_agent(args.agent)
    profile = require_supported(agent)
    if "default_model" not in profile:
        raise AirlockError(f"{agent} needs the guided path: see docs/golden-path.md")
    credential = profile["credential"]
    if not (os.environ.get(credential) or args.model_endpoint):
        raise AirlockError(f"Set {credential} in this shell. It never enters the container")
    task_path = root / TASK_FILE
    if os.path.lexists(task_path):
        raise AirlockError(f"{TASK_FILE} already exists in this project")
    model = args.model or profile["default_model"]
    prices = args.price_per_mtok or profile["default_prices"]
    image = args.image or profile["image"]
    limit = args.max_run_usd or DEFAULT_MAX_RUN_USD
    ensure_image(image, profile["dockerfile"] if image == profile["image"] else None)

    state = State(root)
    endpoint = args.model_endpoint or DEFAULT_ENDPOINTS[profile.get("provider", "anthropic")]
    setup = ["setup", "--path", str(root), "--agent", agent, "--model", model]
    setup += ["--max-run-usd", limit, "--price-per-mtok", prices, "--model-endpoint", endpoint]
    wanted = {
        "agent": agent,
        "model": model,
        "model_endpoint": endpoint,
        "max_run_usd": limit,
        "price_per_mtok": prices,
    }
    if not _approved(state, wanted):
        print(f"\n{agent} will run in a sealed container with a copy of this project.")
        print(f"  It can call one model: {model} at {endpoint}, up to ${limit} a run.")
        print(f"  Prices used for that bound, USD per million tokens: {prices}")
        print("  Input, cache write, cache read, output. Check them against your provider.")
        print("  It has no network, no credentials, and no access to your home directory.")
        print(f"  {credential} stays on this machine, outside the container.\n")
        if not (args.approve or _ask()):
            print("Nothing was approved and nothing ran.")
            return 2
        review = io.StringIO()
        with contextlib.redirect_stdout(review):
            configured = run([*setup, "--approve"])
        if configured:
            print(review.getvalue())
            return configured
        print("Approved and signed. Airlock keeps this in .airlock and airlock_agent.py.")

    runs = state.local / "runs"
    earlier = set(runs.iterdir()) if runs.is_dir() else set()
    receipts = status(state)["receipts"] if state.receipts_path.exists() else 0
    print(f"\n{agent} is working. Ctrl-C stops it, and nothing it did leaves the container.\n")
    task_path.write_text(args.task + "\n")
    try:
        code = run(["work", "--path", str(root), "--message-file", TASK_FILE, "--image", image])
        finished = _new_run(state, earlier)
        if finished is None:
            print("The run did not finish, so there is no result.")
            return code or 2
        try:
            manifest = capture_candidate(state, finished)
        except AirlockError as exc:
            if "changed nothing" not in str(exc):
                raise
            manifest = None
    finally:
        task_path.unlink(missing_ok=True)

    verdict = passed = None
    if manifest and args.tests:
        sha256 = manifest["candidate_sha256"]
        result = verify_candidate(state, sha256, args.tests.resolve())
        verdict = f"{result['verdict']}: {result['detail']}"
        passed = result["verdict"] == TESTS_PASSED
    patch = None
    if manifest:
        patch = state.local / "candidates" / manifest["candidate_sha256"] / "candidate.patch"
    report(
        manifest,
        verdict,
        status(state, since=receipts),
        patch,
        agent_exit=json.loads((finished / "result.json").read_text())["exit_code"],
        spend_limit="$" + limit,
        root=root,
    )
    if code not in FINISHED:
        return code
    return 2 if passed is False else code
