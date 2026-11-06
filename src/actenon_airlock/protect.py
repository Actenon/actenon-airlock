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
import shlex
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


def configured_agent(root: Path) -> str | None:
    """The agent this project was already set up for, if any."""
    try:
        return json.loads((root / ".airlock" / "agent.json").read_text()).get("agent")
    except (OSError, ValueError, AttributeError):
        return None


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


LANGUAGE = {"python": "Python", "go": "Go", "node": "JavaScript/TypeScript"}


def missing_tools(image: str, commands: list[list[str]]) -> list[str]:
    """Programs the planned checks need that the image does not have (asked of the image)."""
    from .workflow import CHECK_PATH

    programs = sorted({c[0] for c in commands})
    script = 'for p in "$@"; do command -v "$p" >/dev/null 2>&1 || echo "$p"; done'
    if "python3" in programs:
        script += '; command -v python3 >/dev/null 2>&1 && { python3 -c "import pytest" 2>/dev/null || echo pytest; }'
    out = Docker().call(
        ["run", "--rm", "--network", "none", "--cap-drop", "ALL", "--entrypoint", "sh",
         "--env", "PATH=" + CHECK_PATH, image, "-c", script, "sh", *programs],
        timeout=60,
    )  # fmt: skip
    return out.split()


def check_plan(root: Path, tests: Path, image: str) -> list[list[str]]:
    """The checks --tests will run, or a refusal before anything is spent."""
    from .workflow import detect_profile, planned_checks

    if not tests.is_dir():
        raise AirlockError(f"--tests {tests} is not a folder. Nothing ran and nothing was spent")
    profile = detect_profile(root)
    commands = planned_checks(root, profile)
    missing = missing_tools(image, commands)
    if missing:
        from .preflight import REPOSITORY, installed_commit

        recipe = (
            f"https://raw.githubusercontent.com/{REPOSITORY.removeprefix('https://github.com/')}/"
            f"{installed_commit() or 'main'}/examples/toolchains/Dockerfile.{profile}"
        )
        tag = f"{root.name.lower() or 'project'}-airlock:{profile}"
        raise AirlockError(
            f"This looks like a {LANGUAGE[profile]} project. Its checks need "
            + ", ".join(f"`{m}`" for m in missing)
            + f", which the image {image} does not have, so they could not run. "
            "Nothing ran and nothing was spent.\n\n"
            "Build an image with your toolchain and dependencies, from your project folder:\n"
            f"  curl -fsSL {recipe} | docker build -t {tag} -f - .\n"
            f"Then add --image {tag} to the same command. Or leave out --tests. "
            "See docs/real-project.md"
        )
    return commands


def _approved(state: State, config: dict) -> bool:
    """Already signed for exactly this run, judged from the signed approval itself.

    agent.json only records what was last proposed; a proposal that was declined must not
    be mistaken for an approval. Changed code stays blocked at dispatch regardless.
    """
    path = state.path / "agent.json"
    if not (state.path / "approved.json").exists() or not path.exists():
        return False
    recorded = json.loads(path.read_text())
    if not all(recorded.get(key) == value for key, value in config.items()):
        return False
    from .agents import parse_prices, usd_to_micro
    from .model_constraints import endpoint

    try:
        signed = state.approved().get("protected_model") or {}
        checks = {
            "model": lambda v: v in signed.get("models", []),
            "model_endpoint": lambda v: endpoint(signed) == v,
            "max_run_usd": lambda v: signed.get("max_run_microusd") == usd_to_micro(v),
            "price_per_mtok": lambda v: signed.get("price_microusd_per_mtok") == parse_prices(v),
        }
        return bool(signed) and all(
            check(config[key]) for key, check in checks.items() if key in config
        )
    except (AirlockError, KeyError, ValueError):
        return False


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


SPEND_BOUND = "Model spend bound reached for this run"


def headline(*, agent_exit, manifest, passed, verdict, stopped_by_budget) -> str:
    """One sentence from observed facts only. An agent saying it is done proves nothing."""
    if stopped_by_budget:
        return "Stopped early: Airlock's spend limit refused a model call, so the agent did not finish."
    if agent_exit not in (0, None):
        return f"The agent did not finish (exit {agent_exit})."
    if manifest is None:
        return "The agent finished but changed nothing."
    if passed is None:
        return "The agent proposed a change. It is not verified: pass --tests DIR to check it."
    if passed:
        return "The agent proposed a change, and your checks passed."
    return f"The agent proposed a change, but your checks did not pass ({verdict.split(':')[0]})."


def report(
    manifest,
    verdict,
    activity,
    patch,
    *,
    agent_exit,
    spend_limit,
    root,
    passed=None,
    receipts_before=0,
) -> None:
    """What happened in this run, in the order a person cares about."""
    blocked, calls = activity["refused"], activity["inference"]
    reasons = activity["refusal_reasons"]
    stopped = any(SPEND_BOUND in reason for reason in reasons)
    print("\nRESULT")
    print("  " + headline(agent_exit=agent_exit, manifest=manifest, passed=passed,
                          verdict=verdict or "", stopped_by_budget=stopped))  # fmt: skip
    print()
    print(f"  Agent     exit {agent_exit}")
    if manifest:
        print(f"  Changed   {len(manifest['changes'])} file(s)")
        for change in manifest["changes"]:
            print(f"              {change['status']:<9}{change['path']}")
    else:
        print("  Changed   nothing")
    print(f"  Checks    {verdict or 'not run. Pass --tests DIR to check it with your own tests'}")
    print(f"  Refused   {blocked} attempt(s)")
    for reason in reasons:
        print(f"              {reason}")
    spent = activity["model_spend"]["estimated_microusd"]
    limit = int(Decimal(spend_limit.lstrip("$")) * 1_000_000)
    print(
        f"  Model     {calls['dispatched']} call(s), about {_usd(spent)} of {_usd(limit)}"
        f" (estimate from signed usage; {_usd(max(limit - spent, 0))} left)"
    )
    if stopped:
        print("  Why it stopped")
        print("            Before each call Airlock reserves that call's worst-case cost. The")
        print(
            f"            next call could have cost more than the {_usd(max(limit - spent, 0))} left,"
        )
        print("            so it was refused and nothing was sent. Your safeguard held; the task")
        print("            is unfinished. To allow longer runs, approve a higher limit:")
        print('              airlock protect --max-run-usd <amount> "<task>"')
    if calls.get("unconfirmed"):
        print(f"  Uncertain {calls['unconfirmed']} model call(s) got no confirmed answer;")
        print("            they are counted at their worst-case cost and are not retried.")
    if activity["unresolved_effects"]:
        print(
            f"  Uncertain {len(activity['unresolved_effects'])} effect(s) with no confirmed outcome"
        )
    print("  External  none: this command never changes anything outside the sealed copy")
    state = "OK" if activity["integrity_ok"] else "FAILED"
    this_run = activity["receipts"] - receipts_before
    earlier = f" ({activity['receipts']} in this project's journal)" if receipts_before else ""
    print(f"  Evidence  {this_run} signed receipt(s) from this run{earlier}, integrity {state}")
    print("            inspect: airlock receipts --path .")
    if manifest:
        relative = patch.relative_to(root)
        print("\nYour project has not been changed. Read the patch, then take it if you want it:")
        print(f"  git apply {relative}")


def broad_folder(root: Path) -> str | None:
    """Why this folder is not one project, or None. A home folder is never a project."""
    root, home = root.resolve(), Path.home().resolve()
    if root == home:
        return "your home folder"
    if root == Path(root.anchor):
        return "the top of the filesystem"
    if home.is_relative_to(root):
        return f"{root}, which holds your home folder"
    return None


def protect(args, root: Path, run) -> int:
    from .workflow import TESTS_PASSED, capture_candidate, status, verify_candidate

    # First, before keys or Docker: a whole home folder must never be handed to an agent.
    where = broad_folder(root)
    if where:
        raise AirlockError(
            f"airlock protect works on one project, and {where} is not one. Nothing ran. "
            "cd into the project first (for example: cd ~/code/my-app), or pass --path"
        )
    agent = choose_agent(args.agent or configured_agent(root))
    profile = require_supported(agent)
    if "default_model" not in profile:
        raise AirlockError(f"{agent} needs the guided path: see docs/golden-path.md")
    credential = profile["credential"]
    if not (os.environ.get(credential) or args.model_endpoint):
        why = "" if args.agent else f"This project is set up for {agent}. "
        raise AirlockError(
            f"{why}Set {credential} in this shell; it never enters the container"
            + ("" if args.agent else ". To use another agent, pass --agent")
        )
    task_path = root / TASK_FILE
    if os.path.lexists(task_path):
        raise AirlockError(f"{TASK_FILE} already exists in this project")
    model = args.model or profile["default_model"]
    prices = args.price_per_mtok or profile["default_prices"]
    image = args.image or profile["image"]
    limit = args.max_run_usd or DEFAULT_MAX_RUN_USD
    from .preflight import require_docker

    if not require_docker("airlock protect " + shlex.quote(args.task)):
        return 2
    ensure_image(image, profile["dockerfile"] if image == profile["image"] else None)
    checks = check_plan(root, args.tests.resolve(), image) if args.tests else None

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
        # Show exactly what would be signed, from the same review the approval uses.
        review = io.StringIO()
        with contextlib.redirect_stdout(review):
            proposed = run(setup)
        if proposed:
            print(review.getvalue())
            return proposed
        print(f"\n{agent} will run in a sealed container with a copy of this project.\n")
        print(review.getvalue().strip())
        if checks:
            shown = "; ".join(" ".join(c) for c in checks)
            print(f"\nAfter the agent finishes, its change is checked with: {shown}")
            print(f"using the tests in {args.tests}, in a sealed container with no network.")
        print("\nCheck the prices above against your provider before you approve.\n")
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
    from datetime import UTC, datetime

    from .progress import live_progress

    log = state.local / "logs" / f"protect-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.log"
    try:
        with live_progress(log):
            code = run(["work", "--path", str(root), "--message-file", TASK_FILE, "--image", image])
        print(f"\nFull agent transcript: {log.relative_to(root)}")
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
    if manifest is None and args.tests:
        verdict = "not run: the agent changed nothing, so there was nothing to check"
    if manifest and args.tests:
        sha256 = manifest["candidate_sha256"]
        result = verify_candidate(
            state, sha256, args.tests.resolve(), image=image,
            accept_skips=args.accept_skips, allow_config_change=args.allow_config_change,
        )  # fmt: skip
        from .workflow import OUTCOMES

        outcome = OUTCOMES.get(result["verdict"], result["verdict"])
        verdict = f"{outcome}: {result['detail']}"
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
        passed=passed,
        receipts_before=receipts,
    )
    if code not in FINISHED:
        return code
    return 2 if passed is False else code
