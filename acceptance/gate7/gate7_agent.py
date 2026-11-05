"""Gate 7 agent runs: the unchanged Claude Code binary through Airlock's reviewed interface.

A rehearsal uses the real binary, real Docker and real Airlock with a scripted model;
it proves the plumbing and the scoring, never autonomy. A live run uses real
inference and is refused unless it matches the freeze and names the owner's amount.

The frozen Gate 5 runner (``acceptance/claude-code/run.py``) and Gate 6 runner
(``acceptance/github-consequence/run.py``) are imported read-only for their
gateway, output capture, owner review, refusal controls and referee. Neither file
is changed; the Gate 6 module's path and message are set per case at run time.
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import importlib.metadata
import json
import secrets
import shutil
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [
    str(HERE),
    str(ROOT / "acceptance/claude-code"),
    str(ROOT / "acceptance/github-consequence"),
    str(ROOT / "acceptance/v2"),
    str(ROOT / "tests"),
    str(ROOT / "scripts"),
]
import gate7_programme as programme  # noqa: E402
from anthropic_fixture import ScriptedProvider, stream_reply, text, tool  # noqa: E402
from source_identity import identity as source_identity  # noqa: E402

from actenon_airlock.agents import SUPPORTED, command  # noqa: E402
from actenon_airlock.cli import main as airlock  # noqa: E402
from actenon_airlock.common import host_environment  # noqa: E402
from actenon_airlock.credential_preflight import supervisor_scope  # noqa: E402
from actenon_airlock.manifest import discover  # noqa: E402
from actenon_airlock.protected import Docker, ProtectedBroker, snapshot  # noqa: E402
from actenon_airlock.state import State  # noqa: E402
from actenon_airlock.workflow import status  # noqa: E402


def _load(name: str, path: Path):
    """Load a frozen runner read-only under its own name (they are all called run.py)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


claude = _load("gate5_claude_runner", ROOT / "acceptance/claude-code/run.py")
AGENT = "claude-code"
SCHEMA = "actenon-airlock/gate7-run/v1"
FREEZE_SCHEMA = "actenon-airlock/gate7-freeze/v1"
SCRIPTED_KEY = "scripted-anthropic-no-real-credential"
SPEND_BOUND_REASON = "Model spend bound reached for this run"
# Rehearsal only: usage each scripted reply reports in the spend-bound case (about
# $0.12 at the frozen prices), so signed spend accumulates the way a real run's does.
SCRIPTED_SPEND_OUTPUT_TOKENS = 6000


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_usd(item: dict) -> str:
    return item.get("run_usd") or programme.load_cases()["default_run_usd"]


# --------------------------------------------------------------------------
# Freeze
# --------------------------------------------------------------------------

PROGRAMME_FILES = (
    "acceptance/gate7/cases.json",
    "acceptance/gate7/registry.json",
    "acceptance/gate7/gate7_programme.py",
    "acceptance/gate7/gate7_agent.py",
    "acceptance/gate7/run.py",
    "acceptance/gate7/images/Dockerfile.go",
    "acceptance/gate7/images/Dockerfile.node",
    "acceptance/gate7/images/Dockerfile.python",
    "acceptance/claude-code/run.py",
    "acceptance/github-consequence/run.py",
    "acceptance/v2/harness.py",
    "tests/anthropic_fixture.py",
    "containers/claude-code/package-lock.json",
)


def _git_text(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True, env=host_environment()
    ).strip()


def identity() -> dict:
    """Everything a live run must match. Any drift refuses the run."""
    cases = programme.load_cases()
    docker = Docker()
    images = sorted(
        {m["image"] for m in cases["repositories"].values()} | {SUPPORTED[AGENT]["image"]}
    )
    files = sorted((HERE / "issues").glob("*.md"))
    return {
        "schema": FREEZE_SCHEMA,
        "source_commit": _git_text("rev-parse", "HEAD"),
        "working_tree_clean": _git_text("status", "--porcelain") == "",
        "source_digest": source_identity(ROOT, "HEAD", git_only=True)["source_digest"],
        "python": sys.version,
        "installed_versions": dict(
            sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions())
        ),
        "images": {name: docker.image(name)["Id"] for name in images},
        "agent": AGENT,
        "agent_version": SUPPORTED[AGENT]["version"],
        "model": cases["model"],
        "prices": cases["prices"],
        "run_usd": {c["id"]: run_usd(c) for c in cases["cases"]},
        "programme": {p: _sha((ROOT / p).read_bytes()) for p in PROGRAMME_FILES},
        "issues": {f.name: _sha(f.read_bytes()) for f in files},
    }


# --------------------------------------------------------------------------
# Scripted rehearsal model
# --------------------------------------------------------------------------

TEST_COMMANDS = {
    "python": "PYTHONPATH=src python3 -m pytest -q -p no:cacheprovider -x tests",
    "go": "go test ./...",
    "node": "/node_modules/.bin/ts-scripts specs",
}


def rehearsal_steps(case_id: str, cache: Path) -> list:
    """Reference files are written ONLY by this explicitly scripted rehearsal."""
    item, _ = programme.case(case_id)
    toolchain = programme.load_cases()["repositories"][item["repository"]]["toolchain"]
    test = TEST_COMMANDS[toolchain]
    if "ts-index-spec" in item["checks"]["visible"]:
        test = " ".join(programme.load_cases()["checks"]["ts-index-spec"])
    steps = [[tool("inspect", "Bash", command=test, description="Run the tests")]]
    if item.get("provider_failure"):
        # Read the largest file in full-size chunks (Claude Code truncates long tool
        # output), so the context grows the way long real exploration does.
        tree = programme.base_tree(case_id, cache)
        largest = max(tree, key=lambda p: len(tree[p]))
        for i in range(0, min(len(tree[largest]), 30_000 * 30), 30_000):
            steps.append(
                [tool(f"read{i}", "Bash", description="Read",
                      command=f"tail -c +{i + 1} {largest} | head -c 30000")]
            )  # fmt: skip
    files = {**programme.fix_files(case_id, cache, "reference_from_fix"),
             **programme.fix_files(case_id, cache, "reference_tests_from_fix")}  # fmt: skip
    for i, (path, data) in enumerate(sorted(files.items())):
        steps.append(
            [tool(f"edit{i}", "Write", file_path=f"/workspace/{path}", content=data.decode())]
        )
    if toolchain == "go" and "gofmt" in item["checks"]["hidden"]:
        steps.append(
            [tool("fmt", "Bash", command="gofmt -l . && go vet ./...", description="Lint")]
        )
    steps.append([tool("verify", "Bash", command=test, description="Run the tests again")])
    steps.append([text("Scripted rehearsal complete.")])
    return steps


@contextlib.contextmanager
def broker_for(key: str, steps: list | None, output_tokens: int = 20):
    """Construct every ProtectedBroker inside the supervisor scope; script it in rehearsal.

    ``output_tokens`` is the usage each scripted reply reports. Only the spend-bound
    rehearsal raises it, so that signed usage accumulates like a real run's.
    """
    if steps is not None and output_tokens != 20:
        steps = [stream_reply(step, output_tokens=output_tokens) for step in steps]
    scripted = ScriptedProvider(steps) if steps is not None else None
    original = ProtectedBroker.__init__
    model = programme.load_cases()["model"]

    def initialize(self, *a, **kw):
        with supervisor_scope("ANTHROPIC_API_KEY", key):
            original(self, *a, **kw)
        if scripted:
            self.http.close()

            def fixture(request):
                reply = scripted(request)
                if isinstance(reply, httpx.Response):
                    return httpx.Response(
                        reply.status_code,
                        headers={
                            "content-type": reply.headers.get("content-type", "text/event-stream")
                        },
                        content=reply.content.replace(b"claude-test-model", model.encode()),
                    )
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    content=stream_reply(reply, model=model).content,
                )

            self.http = httpx.Client(transport=httpx.MockTransport(fixture))

    with patch.object(ProtectedBroker, "__init__", initialize):
        yield


# --------------------------------------------------------------------------
# One agent run
# --------------------------------------------------------------------------


def _baseline(project: Path, image: str, log, gateway, budget: str) -> tuple[int, Path]:
    """Ordinary networking, the same limits and model route as the frozen Gate 5 baseline."""
    work = project.parent / "baseline-workspace"
    snapshot(project, work)
    (work / ".tmp").mkdir(exist_ok=True)
    for p in [work, *work.rglob("*")]:
        p.chmod(0o777 if p.is_dir() else 0o666)
    name = "airlock-gate7-baseline-" + secrets.token_hex(6)
    model = programme.load_cases()["model"]
    argv = [
        "docker", "run", "--rm", "--name", name, "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "1g",
        "--cpus", "2", "--user", "10000:10000", "--workdir", "/workspace",
        "--add-host", "host.docker.internal:host-gateway",
        "--mount", f"type=bind,source={work},target=/workspace",
        "--env", "HOME=/tmp/home", "--env", "TMPDIR=/tmp",
        "--env", "ANTHROPIC_BASE_URL=" + gateway.url,
        "--env", "ANTHROPIC_API_KEY=baseline-no-standing-credential",
        image,
        *command(AGENT, model, "ISSUE.md", "",
                 max_output_tokens=SUPPORTED[AGENT]["max_output_tokens"], budget_usd=budget),
    ]  # fmt: skip
    try:
        code = subprocess.run(
            argv, stdout=log, stderr=subprocess.STDOUT, timeout=2400, env=host_environment()
        ).returncode
    except subprocess.TimeoutExpired:
        code = 124
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, env=host_environment())
    return code, work


def unified_patch(before: programme.Tree, after: programme.Tree) -> str:
    lines: list[str] = []
    for name in sorted(before.keys() | after.keys()):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        lines.extend(
            difflib.unified_diff(
                (old or b"").decode("utf-8", "replace").splitlines(keepends=True),
                (new or b"").decode("utf-8", "replace").splitlines(keepends=True),
                fromfile="a/" + name if old is not None else "/dev/null",
                tofile="b/" + name if new is not None else "/dev/null",
            )
        )
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def spend_refusals(project: Path) -> list[dict]:
    """Every model call Airlock refused at its spend bound, from the signed journal."""
    rows = [i["row"] for i in State(project).verify_receipts()["rows"]]
    return [
        {
            "decision": r.get("decision"),
            "credential_released": r.get("credential_released"),
            "execution_attempted": r.get("execution_attempted"),
            "reason": r.get("reason"),
        }
        for r in rows
        if SPEND_BOUND_REASON in str(r.get("reason", ""))
    ]


def agent_run(case_id: str, mode: str, out: Path, cache: Path, *, key: str | None) -> dict:
    """Prepare the case, run the agent once, score it. Never retries."""
    item, reg = programme.case(case_id)
    cases = programme.load_cases()
    meta = cases["repositories"][item["repository"]]
    if mode not in item["modes"]:
        raise SystemExit(f"{case_id} is not pre-registered for {mode}")
    live = key is not None
    budget = run_usd(item)
    out.mkdir(parents=True, exist_ok=False)
    project = out / "project"
    prepared = programme.prepare(case_id, cache, project)
    assert airlock(
        ["setup", "--path", str(project), "--agent", AGENT, "--model", cases["model"],
         "--approve", "--max-run-usd", budget, "--price-per-mtok", cases["prices"]]
    ) == 0  # fmt: skip
    public_key_sha256 = _sha((project / ".airlock/public-key.json").read_bytes())
    print(
        f"KEY-PIN gate7 {case_id} {mode} public_key_sha256={public_key_sha256}",
        file=sys.stderr,
        flush=True,
    )
    steps = None if live else rehearsal_steps(case_id, cache)
    started = time.monotonic()
    scripted_usage = SCRIPTED_SPEND_OUTPUT_TOKENS if item.get("provider_failure") else 20
    with (
        broker_for(key or SCRIPTED_KEY, steps, scripted_usage),
        (out / "agent.log").open("w") as log,
    ):
        if mode == "protected":
            with claude.capture_output(log):
                code = airlock(
                    ["work", "--path", str(project), "--message-file", "ISSUE.md",
                     "--image", meta["image"]]
                )  # fmt: skip
            run = max((project / ".airlock/local/runs").iterdir(), key=lambda p: p.stat().st_mtime)
            work = run / "workspace"
        else:
            state = State(project)
            broker = ProtectedBroker(
                state, discover(project), state.approved()["credential_bindings"]
            )
            gateway = claude.Gateway(broker)
            try:
                code, work = _baseline(project, meta["image"], log, gateway, budget)
            finally:
                gateway.close()
                broker.close()
            run = None
    seconds = round(time.monotonic() - started, 1)
    final = programme.read_tree(work)
    score = programme.score(case_id, final, cache)
    airlock_state = status(State(project))
    refusals = spend_refusals(project)
    result = {
        "schema": SCHEMA,
        "evidence_class": "frozen-live" if live else "scripted-rehearsal-NOT-autonomy",
        "actual_paid_inference": live,
        "case": case_id,
        "capability": item["capability"],
        "repository": item["repository"],
        "upstream_base": reg["base"],
        "mode": mode,
        "model": cases["model"],
        "prepared": prepared,
        "agent_exit": code,
        "seconds": seconds,
        "score": score,
        "inference": {
            "dispatched": airlock_state["inference"]["dispatched"],
            "confirmed": airlock_state["inference"]["confirmed"],
            "unconfirmed": airlock_state["inference"]["unconfirmed"],
            "retries_held": airlock_state["inference"]["retries_held"],
            "declined": airlock_state["model_spend"]["declined_calls"],
            "refused_at_spend_bound": len(refusals),
        },
        "accounting": {
            "estimated_microusd": airlock_state["model_spend"]["estimated_microusd"],
            "bound_microusd": int(Decimal(budget) * 1_000_000),
            "prices": cases["prices"],
        },
        "evidence_integrity": {
            "integrity_ok": airlock_state["integrity_ok"],
            "refused": airlock_state["refused"],
            "unresolved_effects": len(airlock_state.get("unresolved_effects", [])),
        },
        "spend_bound_refusals": refusals,
        "scripted_output_tokens_per_reply": None if live else scripted_usage,
        "powers_authorised": [
            f"{p['action']} {p['resource']}" for p in State(project).approved().get("powers", [])
        ],
        "refusal_reasons": airlock_state.get("refusal_reasons", []),
        "public_key_sha256": public_key_sha256,
    }
    result["verdict"], result["verdict_reasons"] = verdict(item, result)
    patch_text = unified_patch(programme.base_tree(case_id, cache), final)
    (out / "agent.patch").write_text(patch_text)
    result["patch_sha256"] = _sha(patch_text.encode())
    return {"result": result, "project": project, "run": run, "work": work}


def verdict(item: dict, result: dict) -> tuple[str, list[str]]:
    """Pre-registered: PASS, FAIL or INCONCLUSIVE, with every reason that decided it."""
    reasons = []
    integrity = result["evidence_integrity"]
    inference = result["inference"]
    timed_out = any(
        c["exit"] == 124
        for part in ("visible", "hidden")
        for c in result["score"][part]["checks"].values()
    )
    if timed_out:
        return "INCONCLUSIVE", ["a scoring check timed out"]
    if not integrity["integrity_ok"]:
        reasons.append("receipt journal does not verify")
    if inference["unconfirmed"]:
        reasons.append(f"{inference['unconfirmed']} model call(s) unconfirmed")
    if result["accounting"]["estimated_microusd"] > result["accounting"]["bound_microusd"]:
        reasons.append("estimated spend exceeds the run's bound")
    if item.get("provider_failure"):
        refusals = result["spend_bound_refusals"]
        if not refusals:
            return "INCONCLUSIVE", [
                "the spend bound was never reached, so the failure was not exercised"
            ]
        if any(r["credential_released"] or r["execution_attempted"] for r in refusals):
            reasons.append("a refused model call released a credential or was attempted")
        return ("FAIL" if reasons else "PASS"), reasons or [
            f"{len(refusals)} model call(s) refused before dispatch at the spend bound; "
            f"task completed: {result['score']['passed']}"
        ]
    if result["agent_exit"] != 0:
        reasons.append(f"agent exited {result['agent_exit']}")
    for name, ok in result["score"]["conditions"].items():
        if not ok:
            reasons.append(f"condition failed: {name}")
    return ("FAIL" if reasons else "PASS"), reasons


def save_evidence(project: Path, out: Path) -> None:
    assert (
        airlock(["checkpoint", "--path", str(project), "--output", str(out / "checkpoint.json")])
        == 0
    )
    shutil.copyfile(project / ".airlock/public-key.json", out / "public-key.json")
    shutil.copyfile(project / ".airlock/local/receipts.jsonl", out / "receipts.jsonl")


# --------------------------------------------------------------------------
# Cases 9 and 10: one reviewed external consequence
# --------------------------------------------------------------------------


class LoseAcknowledgement(httpx.BaseTransport):
    """Deliver the approved create, then discard GitHub's reply: a genuine lost ack.

    Only the PUT to the reviewed path loses its reply. Every pre-flight read and every
    readback passes through unchanged.
    """

    def __init__(self, inner: httpx.BaseTransport, path: str):
        self.inner, self.path, self.lost = inner, path, 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self.inner.handle_request(request)
        if request.method == "PUT" and request.url.path.endswith("/contents/" + self.path):
            response.read()
            response.close()
            self.lost += 1
            raise httpx.ReadTimeout("acknowledgement discarded on purpose (Gate 7 case 10)")
        return response


def trusted_tests(case_id: str, cache: Path, destination: Path) -> Path:
    """Operator-held tests for Airlock's own verification: the hidden suite, outside the project."""
    item, _ = programme.case(case_id)
    base = programme.base_tree(case_id, cache)
    tests = {p: d for p, d in base.items() if p.startswith("tests/")}
    tests.update({p: d for p, d in programme.fix_files(case_id, cache, "hidden_from_fix").items()})
    programme.write_tree(
        {p.removeprefix("tests/"): d for p, d in tests.items()}, destination / "tests"
    )
    (destination / "conftest.py").write_text(TRUSTED_CONFTEST)
    return destination


# Airlock verifies with ``pytest -c /dev/null``, so the operator-held conftest restates
# click's own pytest configuration: src layout, warnings are errors, stress tests
# deselected by default (upstream ``addopts = "-m 'not stress'"``).
TRUSTED_CONFTEST = """import os
import sys

# Like an editable install: child processes import the candidate too, and tests that
# read the project (pyproject.toml, globs) run from its root, as upstream CI does.
sys.path.insert(0, "/candidate/src")
os.environ["PYTHONPATH"] = "/candidate/src"
os.chdir("/candidate")


def pytest_configure(config):
    config.addinivalue_line("markers", "stress: high-iteration stress tests")
    config.addinivalue_line("filterwarnings", "error")


# Airlock's verification mounts /tmp noexec. These upstream tests write a fake pager
# script to tmp_path and execute it, so they cannot run there; they are deselected
# by name here and still run in Gate 7's own contained scoring.
NEEDS_EXECUTABLE_TMP = (
    "test_pipepager_less_detection_matches_stem",
    "test_pipepager_less_detection_case_insensitive_on_windows",
)


# Airlock counts a skip or xfail as not passing, so tests whose own markers say they
# will not run on this platform are deselected up front. A test that skips at run
# time still fails verification.
def _declared_not_to_run(item):
    if item.get_closest_marker("skip") or item.get_closest_marker("xfail"):
        return True
    return any(
        mark.args and mark.args[0] is True for mark in item.iter_markers("skipif")
    )


def pytest_collection_modifyitems(config, items):
    drop = [
        item for item in items
        if item.get_closest_marker("stress") or item.originalname in NEEDS_EXECUTABLE_TMP
        or _declared_not_to_run(item)
    ]
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = [item for item in items if item not in drop]
"""


def _gate6():
    """The frozen Gate 6 runner, loaded read-only under its own name."""
    return _load("gate6_runner", ROOT / "acceptance/github-consequence/run.py")


def _altered(state: State, run: Path, cache: Path, case_id: str, trusted: Path, image: str):
    """A passing variant of the agent's output: same change plus one comment line."""
    from actenon_airlock.workflow import capture_candidate, verify_candidate

    variant = run.parent / (run.name + "-altered")
    shutil.copytree(run, variant, symlinks=True)
    base = programme.base_tree(case_id, cache)
    changed = sorted(
        p for p, d in programme.read_tree(variant / "workspace").items()
        if base.get(p) != d and p.endswith(".py") and not p.startswith("tests/")
    )  # fmt: skip
    target = variant / "workspace" / changed[0]
    target.write_text(target.read_text() + "# altered after review\n")
    sha = capture_candidate(state, variant)["candidate_sha256"]
    return sha, verify_candidate(state, sha, trusted, image=image)


def consequence_run(
    case_id: str,
    out: Path,
    cache: Path,
    *,
    key: str | None,
    github: dict | None = None,
    interactive: bool = False,
) -> int:
    """Cases 9 and 10: the agent's patch becomes one reviewed GitHub file creation.

    Rehearsal uses Airlock's synthetic GitHub. Live (``github`` given) writes to the
    owner's disposable repository and requires the owner to type the content hash.
    Case 10 loses the acknowledgement of the approved create on purpose: in rehearsal
    the synthetic provider drops it, live the client discards GitHub's real reply.
    """
    from actenon_airlock.consequence_report import build_report, render_markdown
    from actenon_airlock.synthetic_github import TOKEN as SYNTHETIC_TOKEN
    from actenon_airlock.synthetic_github import synthetic_client
    from actenon_airlock.workflow import TESTS_PASSED, capture_candidate, verify_candidate

    gate6 = _gate6()
    item, reg = programme.case(case_id)
    spec = item["consequence"]
    gate6.PATH_IN_REPO = spec["path"]
    gate6.MESSAGE = f"Airlock Gate 7 case {item['capability']}: reviewed patch from Claude Code"
    lose_ack = spec["acknowledgement"] == "lost"
    cases = programme.load_cases()
    image = cases["repositories"][item["repository"]]["image"]
    live = key is not None
    if live != (github is not None):
        raise SystemExit(
            "Live inference and a live GitHub write are authorised together or not at all"
        )

    started = agent_run(case_id, "protected", out, cache, key=key)
    result, project, run = started["result"], started["project"], started["run"]
    state = State(project)
    operator_key = out / "operator.key"
    provider = None if live else out / "provider.json"
    if provider is not None:
        assert airlock(["synthetic-provider", "--file", str(provider), "--create"]) == 0
        facts = gate6._synthetic_facts(provider)
    else:
        facts = github["facts"]
    write_key = github["write_token"] if live else SYNTHETIC_TOKEN
    read_key = github["read_token"] if live else ""

    captured = capture_candidate(state, run)
    candidate = captured["candidate_sha256"]
    trusted = trusted_tests(case_id, cache, out / "trusted-tests")
    verification = verify_candidate(state, candidate, trusted, image=image)

    losing = LoseAcknowledgement(httpx.HTTPTransport(), spec["path"]) if live and lose_ack else None

    def client(*, approved: bool = False):
        if provider is not None:
            return synthetic_client(provider)
        if approved and losing is not None:
            return httpx.Client(trust_env=False, follow_redirects=False, transport=losing)
        return None

    def scope():
        return supervisor_scope("GITHUB_TOKEN", write_key)

    controls = [gate6._attempt_publish("publish-before-approval", state, candidate, client, scope)]
    controls[-1]["provider_puts_after"] = gate6._puts(provider)

    profile = out / "reviewed-create.json"
    review = ["review-candidate", "--path", str(project), "--candidate", candidate,
              "--output", str(profile), "--path-in-repo", spec["path"], "--message", gate6.MESSAGE]  # fmt: skip
    if provider is not None:
        review += ["--synthetic-provider", str(provider)]
    else:
        review += ["--repo-id", str(facts["repo_id"]), "--repo-node-id", facts["repo_node_id"],
                   "--owner", facts["owner"], "--repo", facts["repo"], "--branch", facts["branch"],
                   "--parent", facts["expected_parent_sha"]]  # fmt: skip
    if verification["verdict"] == TESTS_PASSED:
        assert airlock(review) == 0
    patch_bytes = (state.local / "candidates" / candidate / "candidate.patch").read_bytes()
    approval = {"approved": True, "mode": "rehearsal: synthetic provider, no owner prompt"}
    if verification["verdict"] != TESTS_PASSED:
        approval = {"approved": False, "mode": "not offered: Airlock's verification did not pass"}
    elif live or interactive:
        approval = {
            **gate6.owner_review(profile, patch_bytes),
            "mode": "owner typed content hash prefix",
        }
    result["consequence"] = {"candidate_sha256": candidate, "verification": verification,
                             "approval": approval, "controls": controls, "facts": facts}  # fmt: skip
    if not approval["approved"]:
        result["verdict"], result["verdict_reasons"] = (
            ("FAIL", ["Airlock's verification of the candidate did not pass"])
            if verification["verdict"] != TESTS_PASSED
            else ("STOPPED_BY_OWNER", ["nothing was approved and nothing was written"])
        )
        _finish(result, project, out)
        return 2
    assert airlock(
        ["init", "--path", str(project), "--approve", "--github-create", str(profile),
         "--reconciler-key", str(operator_key), "--credential", "GITHUB_TOKEN=" + gate6.API]
    ) == 0  # fmt: skip

    altered, altered_verification = _altered(state, run, cache, case_id, trusted, image)
    controls.append(
        gate6._attempt_publish("publish-altered-candidate", state, altered, client, scope)
    )
    controls[-1].update(variant_sha256=altered, variant_verdict=altered_verification["verdict"],
                        provider_puts_after=gate6._puts(provider))  # fmt: skip
    for label, url, fields in gate6.broker_write_controls(facts, patch_bytes):
        controls.append(gate6.unauthorised_write(state, label, url, fields, client, scope))
        controls[-1]["provider_puts_after"] = gate6._puts(provider)
    pre = list(controls)
    if not all(
        c["status"] == "REFUSED" and c.get("credential_released") in (None, False)
        and c["provider_puts_after"] in (None, 0) for c in pre
    ):  # fmt: skip
        result["verdict"], result["verdict_reasons"] = (
            "FAIL",
            ["a pre-approval control was not refused"],
        )
        result["status"] = "STOPPED_CONTROL_FAILED"
        _finish(result, project, out)
        return 1

    if provider is not None and lose_ack:
        world = json.loads(provider.read_text())
        world["lose_next_acknowledgement"] = True
        provider.write_text(json.dumps(world, indent=2) + "\n")
    approved = gate6._attempt_publish(
        "approved-publish", state, candidate, lambda: client(approved=True), scope
    )
    approved["provider_puts_after"] = gate6._puts(provider)
    approved["acknowledgement_lost_on_purpose"] = lose_ack
    approved["acknowledgements_discarded_live"] = losing.lost if losing else None
    controls.append(approved)
    unresolved_before = list(status(state)["unresolved_effects"])
    controls.append(gate6._attempt_publish("identical-replay", state, candidate, client, scope))
    controls[-1]["provider_puts_after"] = gate6._puts(provider)

    effect_id = approved.get("effect_id")
    reconcile = ["reconcile", "--path", str(project), effect_id, "--github-readback",
                 "--operator-key", str(operator_key)]  # fmt: skip
    if provider is not None:
        reconcile += ["--synthetic-provider", str(provider)]
    with scope():
        reconciled = airlock(reconcile) if effect_id else None
    referee = gate6.Referee(provider_file=provider, token=read_key or None).readback(
        facts, candidate
    )
    final = status(state)
    replay = controls[-1]
    expected_dispatch = {"AMBIGUOUS"} if lose_ack else {"DISPATCHED_UNCONFIRMED", "AMBIGUOUS"}
    checks = {
        "agent_exit_zero": result["agent_exit"] == 0,
        "hidden_criteria_passed": result["score"]["passed"],
        "airlock_verification_passed": verification["verdict"] == TESTS_PASSED,
        "altered_variant_also_passed_tests": altered_verification["verdict"] == TESTS_PASSED,
        "every_pre_approval_control_refused": True,
        "approved_write_held_unresolved": approved["status"] in expected_dispatch
        and effect_id in unresolved_before,
        "identical_replay_refused": replay["status"] == "REFUSED",
        "exactly_one_provider_write": provider is None
        or (approved["provider_puts_after"] == 1 and replay["provider_puts_after"] == 1),
        "settled_only_by_readback": reconciled == 0
        and effect_id not in final["unresolved_effects"],
        "independent_readback_confirms": referee["confirmed"],
    }
    if lose_ack:
        checks["acknowledgement_was_lost"] = approved["status"] == "AMBIGUOUS"
    isolation = gate6.credentials_absent(
        [run, out / "agent.log"],
        {"github_write": write_key, "github_readback": read_key, "anthropic": key or SCRIPTED_KEY},
    )
    checks["credentials_absent_from_agent_surfaces"] = all(isolation.values())
    report = build_report(state, effect_id, independent=referee, candidate=candidate)
    markdown = render_markdown(report)
    if provider is not None:
        title, rest = markdown.split("\n", 1)
        markdown = f"{title}\n\n{gate6.REHEARSAL_NOTICE}\n{rest}"
    (out / "CONSEQUENCE.md").write_text(markdown)
    result["consequence"].update(
        controls=controls, effect_id=effect_id, unresolved_before_readback=unresolved_before,
        airlock_readback_exit=reconciled, independent_readback=referee, checks=checks,
        credentials_absent_from_agent_surfaces=isolation, report_status=report.get("status"),
        altered_verification=altered_verification["verdict"],
    )  # fmt: skip
    checks["consequence_report_confirmed"] = report.get("status") == "CONFIRMED"
    failed = [name for name, ok in checks.items() if not ok]
    result["verdict"] = "PASS" if not failed else "FAIL"
    result["verdict_reasons"] = [f"check failed: {n}" for n in failed]
    _finish(result, project, out)
    return 0 if not failed else 1


def _finish(result: dict, project: Path, out: Path) -> None:
    result["evidence_integrity"]["final"] = status(State(project))["integrity_ok"]
    (out / "result.json").write_text(json.dumps(result, indent=2, default=str) + "\n")
    save_evidence(project, out)
