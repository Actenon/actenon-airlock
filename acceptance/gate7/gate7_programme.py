"""Gate 7: three upstream repositories, ten pre-registered agent cases.

This module holds everything that does not involve an agent: resolving the frozen
upstream objects, building a case workspace, and scoring a tree in a contained,
no-network container. ``run.py`` drives the agent.

Integrity rules, enforced here:

* A workspace is the upstream tree at the fix's parent plus listed overlays, with
  no git history. The fix, the hidden tests and the reference source are read
  from the verified upstream clone only when scoring or in a scripted rehearsal.
* Every upstream object is named by its full git id in ``registry.json``; a clone
  whose objects differ is refused.
* Scoring restores the original tests, overlays the hidden tests and runs every
  check with ``--network none`` on a read-only root, as an unprivileged user.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CASES_PATH = HERE / "cases.json"
REGISTRY_PATH = HERE / "registry.json"
ISSUES = HERE / "issues"
REGISTRY_SCHEMA = "actenon-airlock/gate7-registry/v1"
SCORE_SCHEMA = "actenon-airlock/gate7-score/v1"
# Never part of a scored tree: tool caches, build output, the task file.
SKIP = frozenset(
    {".git", ".airlock", ".tmp", ".home", "node_modules", "__pycache__", ".pytest_cache",
     "dist", ".vitest-cache", ".ruff_cache", ".mypy_cache"}
)  # fmt: skip
TASK_FILE = "ISSUE.md"
# Root files Airlock itself places in a run workspace (its in-container launcher).
RUNTIME_FILES = frozenset({TASK_FILE, "airlock_agent.py"})
CHECK_TIMEOUT = 900


class ProgrammeError(Exception):
    pass


def _environment() -> dict[str, str]:
    """Host subprocesses get only what they need; no credential can be inherited."""
    keep = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "TMPDIR", "LANG")
    return {k: os.environ[k] for k in keep if k in os.environ}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_cases() -> dict:
    return json.loads(CASES_PATH.read_text())


def load_registry() -> dict:
    registry = json.loads(REGISTRY_PATH.read_text())
    if registry.get("schema") != REGISTRY_SCHEMA:
        raise ProgrammeError("registry.json has an unknown schema")
    if registry["cases_sha256"] != sha256(CASES_PATH.read_bytes()):
        raise ProgrammeError("cases.json changed after registration; register again and review")
    return registry


def case(case_id: str) -> tuple[dict, dict]:
    defined = {c["id"]: c for c in load_cases()["cases"]}
    if case_id not in defined:
        raise ProgrammeError(f"unknown case {case_id}")
    return defined[case_id], load_registry()["cases"][case_id]


# --------------------------------------------------------------------------
# Upstream objects
# --------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=_environment())
    if proc.returncode != 0:
        raise ProgrammeError(f"git {' '.join(args)} failed in {repo}: {proc.stderr.decode()[:300]}")
    return proc.stdout


def _rev(repo: Path, spec: str) -> str:
    return _git(repo, "rev-parse", "--verify", spec).decode().strip()


def upstream(cache: Path, name: str, url: str) -> Path:
    repo = cache / name
    if not (repo / ".git").is_dir():
        raise ProgrammeError(f"no upstream clone of {url} at {repo}; run 'run.py fetch' first")
    origin = _git(repo, "remote", "get-url", "origin").decode().strip()
    if origin.removesuffix(".git") != url.removesuffix(".git"):
        raise ProgrammeError(f"{repo} is a clone of {origin}, not {url}")
    return repo


def blob(repo: Path, commit: str, path: str, expected: str | None = None) -> bytes:
    object_id = _rev(repo, f"{commit}:{path}")
    if expected is not None and object_id != expected:
        raise ProgrammeError(f"{path} at {commit[:12]} is {object_id}, registered {expected}")
    return _git(repo, "cat-file", "blob", object_id)


def register(cache: Path) -> dict:
    """Resolve every short id in cases.json to full, content-addressed upstream ids."""
    spec = load_cases()
    out = {
        "schema": REGISTRY_SCHEMA,
        "cases_sha256": sha256(CASES_PATH.read_bytes()),
        "repositories": {},
        "cases": {},
    }
    for name, meta in spec["repositories"].items():
        repo = upstream(cache, name, meta["url"])
        entry = {"url": meta["url"], "licence": meta["licence"]}
        lock = meta.get("dependency_lock")
        if lock:
            commit = _rev(repo, lock["commit"] + "^{commit}")
            entry["dependency_lock"] = {
                "commit": commit,
                "blobs": {p: _rev(repo, f"{commit}:{p}") for p in lock["paths"]},
            }
        out["repositories"][name] = entry
    for item in spec["cases"]:
        repo = upstream(cache, item["repository"], spec["repositories"][item["repository"]]["url"])
        fix = _rev(repo, item["fix"] + "^{commit}")
        parents = _git(repo, "rev-list", "--parents", "-n", "1", fix).decode().split()[1:]
        if len(parents) != 1:
            raise ProgrammeError(f"{item['id']}: fix {fix} must have exactly one parent")
        base = parents[0]
        paths = sorted(
            {*item.get("overlay_from_fix", []), *item["hidden_from_fix"],
             *item["reference_from_fix"], *item.get("reference_tests_from_fix", [])}
        )  # fmt: skip
        out["cases"][item["id"]] = {
            "repository": item["repository"],
            "fix": fix,
            "fix_committed": _git(repo, "show", "-s", "--format=%cI", fix).decode().strip(),
            "fix_subject": _git(repo, "show", "-s", "--format=%s", fix).decode().strip(),
            "base": base,
            "base_tree": _rev(repo, base + "^{tree}"),
            "fix_blobs": {p: _rev(repo, f"{fix}:{p}") for p in paths},
            "issue_sha256": sha256((ISSUES / f"{item['id']}.md").read_bytes()),
        }
    return out


# --------------------------------------------------------------------------
# Trees
# --------------------------------------------------------------------------

Tree = dict[str, bytes]


def read_tree(root: Path) -> Tree:
    """Regular files, skipping caches and build output. Links refuse the tree."""
    found: Tree = {}
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        for name in sorted(files):
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            if rel in RUNTIME_FILES:
                continue
            if path.is_symlink() or not path.is_file():
                raise ProgrammeError(f"tree contains a link or special file: {rel}")
            found[rel] = path.read_bytes()
        for name in dirs:
            if (Path(current) / name).is_symlink():
                raise ProgrammeError(f"tree contains a directory link: {name}")
    return found


def write_tree(tree: Tree, root: Path) -> None:
    for rel, data in tree.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _archive(repo: Path, commit: str) -> Tree:
    data = _git(repo, "archive", "--format=tar", commit)
    tree: Tree = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            if not member.isfile():
                raise ProgrammeError(f"upstream {commit[:12]} contains a link: {member.name}")
            tree[member.name] = archive.extractfile(member).read()
    return tree


def is_test(toolchain: str, path: str) -> bool:
    if toolchain == "python":
        return path.startswith("tests/")
    if toolchain == "go":
        return path.endswith("_test.go") or "/testdata/" in "/" + path
    if toolchain == "node":
        return path.endswith(".spec.ts")
    raise ProgrammeError(f"unknown toolchain {toolchain}")


def _repo_for(case_id: str, cache: Path) -> tuple[dict, dict, dict, Path]:
    item, reg = case(case_id)
    meta = load_cases()["repositories"][item["repository"]]
    return item, reg, meta, upstream(cache, item["repository"], meta["url"])


def base_tree(case_id: str, cache: Path) -> Tree:
    """The agent's starting tree: upstream parent of the fix, plus listed overlays."""
    item, reg, _, repo = _repo_for(case_id, cache)
    if _rev(repo, reg["base"] + "^{tree}") != reg["base_tree"]:
        raise ProgrammeError(f"{case_id}: upstream base tree differs from the registry")
    tree = _archive(repo, reg["base"])
    for path in item.get("overlay_from_fix", []):
        tree[path] = blob(repo, reg["fix"], path, reg["fix_blobs"][path])
    if item.get("overlay_from_dependency_lock"):
        lock = load_registry()["repositories"][item["repository"]]["dependency_lock"]
        for path in item["overlay_from_dependency_lock"]:
            tree[path] = blob(repo, lock["commit"], path, lock["blobs"][path])
    return tree


def fix_files(case_id: str, cache: Path, key: str) -> Tree:
    """Hidden tests or reference files, read only from the verified upstream fix."""
    item, reg, _, repo = _repo_for(case_id, cache)
    return {p: blob(repo, reg["fix"], p, reg["fix_blobs"][p]) for p in item.get(key, [])}


def prepare(case_id: str, cache: Path, destination: Path) -> dict:
    """Write the workspace the agent receives, and describe it."""
    item, reg = case(case_id)
    issue = (ISSUES / f"{case_id}.md").read_bytes()
    if sha256(issue) != reg["issue_sha256"]:
        raise ProgrammeError(f"{case_id}: issue statement changed after registration")
    tree = base_tree(case_id, cache)
    leaked = [
        p
        for p, data in {**fix_files(case_id, cache, "reference_from_fix")}.items()
        if tree.get(p) == data
    ]
    if leaked:
        raise ProgrammeError(f"{case_id}: the workspace already holds the reference for {leaked}")
    destination.mkdir(parents=True, exist_ok=False)
    write_tree(tree, destination)
    (destination / TASK_FILE).write_bytes(issue)
    return {
        "case": case_id,
        "upstream": reg["base"],
        "files": len(tree),
        "tree_sha256": tree_digest(tree),
        "issue_sha256": reg["issue_sha256"],
        "git_history": "none",
    }


def tree_digest(tree: Tree) -> str:
    digest = hashlib.sha256()
    for name in sorted(tree):
        digest.update(name.encode() + b"\0" + hashlib.sha256(tree[name]).digest())
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Contained checks
# --------------------------------------------------------------------------


def contained(image: str, tree: Tree, argv: list[str], toolchain: str) -> dict:
    """Run one check on a private copy of the tree: no network, read-only root."""
    env = {"HOME": "/tmp", "TMPDIR": "/tmp", "NO_COLOR": "1", "CI": "1",
           "PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}  # fmt: skip
    if toolchain == "python":
        env["PYTHONPATH"] = "/tmp/w/src"
    if toolchain == "go":
        env.update(GOCACHE="/tmp/gocache", GOFLAGS="-mod=mod", GOPROXY="off", GOTOOLCHAIN="local")
    with tempfile.TemporaryDirectory(prefix="airlock-gate7-score-") as tmp:
        source = Path(tmp) / "src"
        source.mkdir()
        write_tree(tree, source)
        for path in [source, *source.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        command = [
            "docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,exec,size=1g", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "512", "--memory", "2g",
            "--cpus", "2", "--user", "65534:65534",
            *[a for k, v in env.items() for a in ("--env", f"{k}={v}")],
            "--mount", f"type=bind,source={source},target=/src,readonly",
            "--entrypoint", "sh", image,
            "-c", 'cp -R /src /tmp/w && cd /tmp/w && exec "$@"', "sh", *argv,
        ]  # fmt: skip
        started = time.monotonic()
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=CHECK_TIMEOUT, env=_environment()
            )
            code, output = proc.returncode, proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            code, output = 124, "timed out"
    lines = [line for line in output.strip().splitlines() if line.strip()]
    return {"exit": code, "seconds": round(time.monotonic() - started, 1), "tail": lines[-4:]}


def _run_checks(names: list[str], image: str, tree: Tree, toolchain: str) -> dict:
    commands = load_cases()["checks"]
    results = {name: contained(image, tree, commands[name], toolchain) for name in names}
    return {"passed": all(r["exit"] == 0 for r in results.values()), "checks": results}


def _docstring(source: bytes, function: str) -> str | None:
    try:
        module = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef) and node.name == function:
            return ast.get_docstring(node)
    return None


def score(case_id: str, final: Tree, cache: Path, image: str | None = None) -> dict:
    """Score a final tree against the pre-registered visible and hidden criteria."""
    item, reg = case(case_id)
    meta = load_cases()["repositories"][item["repository"]]
    toolchain, image = meta["toolchain"], image or meta["image"]
    base = base_tree(case_id, cache)
    changed = sorted(p for p in base.keys() | final.keys() if base.get(p) != final.get(p))
    tests_changed = [p for p in changed if is_test(toolchain, p)]
    source_changed = [p for p in changed if not is_test(toolchain, p)]
    # An original test file the upstream change rewrote is scored in its updated
    # form: the issue changes the behaviour it asserted, and other tests may import it.
    superseded = set(item["hidden_from_fix"]) - set(item.get("overlay_from_fix", []))
    hidden_files = fix_files(case_id, cache, "hidden_from_fix")
    original_tests = {
        p: (hidden_files[p] if p in superseded else d)
        for p, d in base.items()
        if is_test(toolchain, p)
    }
    # Editing a test the upstream change also had to update is legitimate; any other
    # change to a pre-existing test is not.
    existing_tests_changed = [p for p in tests_changed if p in base and p not in superseded]
    visible_tree = {**{p: d for p, d in final.items() if not is_test(toolchain, p)},
                    **original_tests}  # fmt: skip
    hidden_tree = {**visible_tree, **hidden_files}
    result = {
        "schema": SCORE_SCHEMA,
        "case": case_id,
        "image": image,
        "files_changed": changed,
        "source_files_changed": source_changed,
        "test_files_changed": tests_changed,
        "existing_tests_changed": existing_tests_changed,
        "superseded_by_hidden": sorted(superseded & base.keys()),
        "visible": _run_checks(item["checks"]["visible"], image, visible_tree, toolchain),
        "hidden": _run_checks(item["checks"]["hidden"], image, hidden_tree, toolchain),
    }
    conditions = {
        "source_changed": bool(source_changed),
        "visible_passed": result["visible"]["passed"],
        "hidden_passed": result["hidden"]["passed"],
    }
    if item.get("agent_tests_must_detect_base"):
        added = {p: final[p] for p in tests_changed if p in final}
        on_base = {**base, **added}
        result["agent_tests"] = {
            "files": sorted(added),
            "on_final": _run_checks(item["checks"]["visible"], image, final, toolchain),
            "on_base": _run_checks(item["checks"]["visible"], image, on_base, toolchain),
        }
        conditions["agent_tests_pass_on_final"] = (
            bool(added) and (result["agent_tests"]["on_final"]["passed"])
        )
        conditions["agent_tests_fail_on_base"] = bool(added) and (
            not result["agent_tests"]["on_base"]["passed"]
        )
    else:
        conditions["existing_tests_unmodified"] = not existing_tests_changed
    for path in item.get("unchanged_paths", []):
        conditions[f"unchanged:{path}"] = base.get(path) == final.get(path)
    interface = item.get("documented_interface")
    if interface:
        conditions["documented_interface_updated"] = _docstring(
            final.get(interface["path"], b""), "style"
        ) not in (None, _docstring(base.get(interface["path"], b""), "style"))
    result["conditions"] = conditions
    result["passed"] = all(conditions.values())
    return result


def reference_tree(case_id: str, cache: Path) -> Tree:
    """The upstream fix applied to the base: used only to validate the criteria."""
    return {
        **base_tree(case_id, cache),
        **fix_files(case_id, cache, "reference_from_fix"),
        **fix_files(case_id, cache, "reference_tests_from_fix"),
    }


def prestate(case_id: str, cache: Path) -> dict:
    """The initial state must fail the hidden criteria; the upstream fix must pass them."""
    item, reg = case(case_id)
    meta = load_cases()["repositories"][item["repository"]]
    toolchain, image = meta["toolchain"], meta["image"]
    base = base_tree(case_id, cache)
    hidden = fix_files(case_id, cache, "hidden_from_fix")
    overlaid = set(item.get("overlay_from_fix", []))
    initial = {
        "visible": _run_checks(item["checks"]["visible"], image, base, toolchain),
        "hidden": _run_checks(item["checks"]["hidden"], image, {**base, **hidden}, toolchain),
    }
    reference = score(case_id, reference_tree(case_id, cache), cache)
    expected = item["expect_base"]
    observed = {k: "pass" if initial[k]["passed"] else "fail" for k in ("visible", "hidden")}
    hidden_absent = all(base.get(p) != d for p, d in hidden.items() if p not in overlaid)
    return {
        "case": case_id,
        "upstream_base": reg["base"],
        "upstream_fix": reg["fix"],
        "fix_committed": reg["fix_committed"],
        "workspace_tree_sha256": tree_digest(base),
        "workspace_files": len(base),
        "initial": initial,
        "initial_matches_expectation": observed == expected,
        "observed": observed,
        "expected": expected,
        "hidden_tests_absent_from_workspace": hidden_absent,
        "reference": reference,
        "reference_passes": reference["passed"],
        "valid": observed == expected and reference["passed"] and hidden_absent,
    }


def fetch(cache: Path) -> dict:
    """Trusted preparation: clone each upstream repository once (network)."""
    cache.mkdir(parents=True, exist_ok=True)
    done = {}
    for name, meta in load_cases()["repositories"].items():
        if not (cache / name / ".git").is_dir():
            subprocess.run(
                ["git", "clone", "--quiet", meta["url"], str(cache / name)],
                check=True, env=_environment(),
            )  # fmt: skip
        done[name] = str(cache / name)
    return done


def node_context(cache: Path, destination: Path) -> Path:
    """Build context for the Node image: the frozen lockfile, nothing else."""
    registry = load_registry()
    meta = load_cases()["repositories"]["path-to-regexp"]
    lock = registry["repositories"]["path-to-regexp"]["dependency_lock"]
    repo = upstream(cache, "path-to-regexp", meta["url"])
    destination.mkdir(parents=True, exist_ok=True)
    for path, object_id in lock["blobs"].items():
        (destination / path).write_bytes(blob(repo, lock["commit"], path, object_id))
    shutil.copyfile(HERE / "images/Dockerfile.node", destination / "Dockerfile")
    return destination
