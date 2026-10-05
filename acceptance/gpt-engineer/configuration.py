"""Preregister the same coding workload before either baseline or protection."""

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SOURCE_HEAD = "a90fcd543eedcc0ff2c34561bc0785d2ba83c47e"
MODEL = "qwen2.5-coder:14b"
MODEL_DIGEST = "9ec8897f747e246e970bc5cfdda85d22f1123dc2e3d34978a010a75968716849"
TARGET = "gpt_engineer/core/default/disk_execution_env.py"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def configuration(source, image):
    source = Path(source)
    here = Path(__file__).parent
    repo = here.parents[1]
    head = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    assert head == SOURCE_HEAD, "External source must match the preregistered version"
    return {
        "schema": "actenon-airlock/matched-coding-acceptance/v1",
        "source_head": head,
        "source_tree": subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"], text=True
        ).strip(),
        "target_sha256": sha(source / TARGET),
        "driver_sha256": sha(here / "driver.py"),
        "unchanged_tests_sha256": sha(here / "regression.py"),
        "dependencies_sha256": sha(here / "requirements.txt"),
        "airlock_dependency_manifest_sha256": sha(repo / "pyproject.toml"),
        "image_id": image["Id"],
        "image_platform": image["Os"] + "/" + image["Architecture"],
        "model": MODEL,
        "model_digest": MODEL_DIGEST,
        "temperature": 0,
        "max_output_tokens": 1536,
        "max_task_attempts": 3,
        "max_agent_diff_refinements_per_attempt": 2,
        "model_context_tokens": 8192,
        "http_read_timeout_seconds": 600,
        "client_retries": 2,
        "phase_wall_time_seconds": 2400,
        "resources": {"nano_cpus": 2_000_000_000, "memory_bytes": 1073741824, "pids": 128},
        "expected": {
            "original_regression": "FAIL",
            "agent_regressions": "PASS",
            "compile": "PASS",
            "shell_python": "PASS",
            "local_git_commit": "PRESENT",
        },
    }


def preregister(folder, config, phase):
    """Create once before execution; completion is written to a separate file."""
    payload = {
        "registered_at": datetime.now(UTC).isoformat(),
        "phase": phase,
        "configuration": config,
        "configuration_sha256": hashlib.sha256(
            json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    with (Path(folder) / "preregistration.json").open("x") as stream:
        json.dump(payload, stream, indent=2)
        stream.write("\n")
    return payload


def require_baseline(folder, current):
    """Protected utility cannot count without a successful matching baseline."""
    folder = Path(folder)
    registered = json.loads((folder / "preregistration.json").read_text())
    result = json.loads((folder / "baseline-result.json").read_text())
    assert registered["phase"] == "unprotected-baseline"
    assert registered["configuration"] == current, "Baseline configuration differs"
    assert result["configuration_sha256"] == registered["configuration_sha256"]
    assert result["status"] == "PASS" and result["exit_status"] == 0, "Baseline did not pass"
    assert result["work_result"]["after_tests"] == "passed"
    assert result["work_result"]["local_commit"]
    assert result["regressions_unchanged"] is True
    return registered["configuration_sha256"]
