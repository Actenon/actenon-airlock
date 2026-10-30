"""Check every v2 task is meaningful, inside a no-network container.

The unmodified repo must fail its visible tests and at least one hidden test, and
the reference fix must pass both. Reference fixes are never given to an agent.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "actenon-airlock-compute:dev"


def pytest(root: Path, target: str) -> int:
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
         "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONPATH=/work",
         "--mount", f"type=bind,src={root},dst=/work,readonly", "-w", "/work", IMAGE,
         "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", target],
        capture_output=True, text=True, timeout=120,
    ).returncode  # fmt: skip


def stage(task: Path, tmp: Path, name: str, reference: bool) -> Path:
    root = tmp / name
    shutil.copytree(task / "repo", root)
    shutil.copy(task / "scoring" / "test_hidden.py", root / "test_hidden.py")
    if reference:
        shutil.copytree(task / "scoring" / "reference", root, dirs_exist_ok=True)
    root.chmod(0o755)
    for path in root.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return root


report = {}
with tempfile.TemporaryDirectory(prefix="v2-validate-") as tmp:
    tmp = Path(tmp)
    for task in sorted((HERE / "tasks").iterdir()):
        if not (task / "repo").is_dir():
            continue
        buggy = stage(task, tmp, task.name + "-buggy", False)
        fixed = stage(task, tmp, task.name + "-fixed", True)
        report[task.name] = {
            "visible_fails_before": pytest(buggy, "tests") == 1,
            "hidden_fails_before": pytest(buggy, "test_hidden.py") == 1,
            "visible_passes_with_reference": pytest(fixed, "tests") == 0,
            "hidden_passes_with_reference": pytest(fixed, "test_hidden.py") == 0,
        }
print(json.dumps(report, indent=2))
sys.exit(0 if all(all(v.values()) for v in report.values()) else 1)
