"""Matched unprotected task baseline: direct local model, no Airlock authority path.

The coding process retains the same CPU/memory/PID limits and copied workspace.
Only its model route differs: Linux host networking reaches the disposable local
model directly. No production credentials, accounts or mutation targets are used.
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from configuration import TARGET, configuration, preregister, sha

from actenon_airlock.protected import Docker, snapshot

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--case", type=Path, required=True)
parser.add_argument("--evidence", type=Path, required=True)
parser.add_argument("--image", default="actenon-airlock-gpt-engineer:acceptance")
args = parser.parse_args()
assert sys.platform == "linux", "This matched host-network baseline is registered for Linux"
source, case, evidence = args.source.resolve(), args.case.resolve(), args.evidence.resolve()
evidence.mkdir(parents=True, exist_ok=False)
docker = Docker()
engine = docker.verify_engine()
image = docker.image(args.image)
registered = preregister(evidence, configuration(source, image), "unprotected-baseline")
shutil.copytree(source, case, ignore=shutil.ignore_patterns(".git", "__pycache__"))
for name, destination in (
    ("driver.py", "acceptance_driver.py"),
    ("regression.py", "test_airlock_execution_regression.py"),
):
    shutil.copyfile(Path(__file__).with_name(name), case / destination)
workspace = case.parent / (case.name + "-workspace")
snapshot(case, workspace)
for name in (".home", ".tmp"):
    (workspace / name).mkdir()
    (workspace / name).chmod(0o777)
empty = [
    item
    for entry in image["Config"].get("Env", [])
    for item in ("--env", entry.split("=", 1)[0] + "=")
]
environment = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/workspace/.home",
    "TMPDIR": "/workspace/.tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TIKTOKEN_CACHE_DIR": "/opt/airlock/tiktoken",
    "OPENAI_BASE_URL": "http://127.0.0.1:11434/v1",
    "OPENAI_API_BASE": "http://127.0.0.1:11434/v1",
    "OPENAI_API_KEY": "airlock-no-standing-credential",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "safe.directory",
    "GIT_CONFIG_VALUE_0": "/workspace",
}
identity = None
result = {
    "configuration_sha256": registered["configuration_sha256"],
    "started_at": datetime.now(UTC).isoformat(),
    "status": "FAIL",
    "phase": "unprotected-baseline",
    "protected_acceptance": False,
}
try:
    identity = docker.call(
        [
            "create",
            "--pull",
            "never",
            "--network",
            "host",
            "--read-only",
            "--no-healthcheck",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--ipc",
            "private",
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
            "--entrypoint",
            "python3",
            *empty,
            *[item for key, value in environment.items() for item in ("--env", key + "=" + value)],
            "--mount",
            f"type=bind,source={workspace},target=/workspace",
            image["Id"],
            "acceptance_driver.py",
            "--phase",
            "baseline",
        ]
    )
    inspected = docker.json(["inspect", identity])[0]
    host = inspected["HostConfig"]
    assert host["NanoCpus"] == 2_000_000_000 and host["Memory"] == 1073741824
    assert host["PidsLimit"] == 128 and host["NetworkMode"] == "host"
    assert inspected["Config"]["User"] == "10000:10000"
    assert host["ReadonlyRootfs"] and not host["Privileged"]
    assert host["CapDrop"] == ["ALL"] and not host.get("CapAdd")
    assert "no-new-privileges" in host["SecurityOpt"]
    assert len(inspected["Mounts"]) == 1
    mount = inspected["Mounts"][0]
    assert (
        mount["Source"] == str(workspace) and mount["Destination"] == "/workspace" and mount["RW"]
    )
    (evidence / "baseline-container.json").write_text(
        json.dumps(
            {
                "engine": engine,
                "image_id": image["Id"],
                "host_config": host,
                "mounts": inspected["Mounts"],
                "environment": environment,
                "network_difference": "Host-network direct inference; no Airlock proxy or authorization",
            },
            indent=2,
        )
        + "\n"
    )
    with (evidence / "baseline-console.log").open("w") as stream:
        run = subprocess.run(
            [docker.binary, "start", "--attach", identity],
            env=docker.environment,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=2400,
            check=False,
        )
    result["exit_status"] = docker.json(["inspect", identity])[0]["State"]["ExitCode"]
    result["attach_exit_status"] = run.returncode
    result["regressions_unchanged"] = (
        sha(workspace / "test_airlock_execution_regression.py")
        == registered["configuration"]["unchanged_tests_sha256"]
    )
    if (workspace / "work-result.json").exists():
        result["work_result"] = json.loads((workspace / "work-result.json").read_text())
    assert result["exit_status"] == 0 and run.returncode == 0, "Matched baseline failed"
    assert result["regressions_unchanged"], "Baseline changed the frozen tests"
    assert (
        result["work_result"]["after_tests"] == "passed" and result["work_result"]["local_commit"]
    )
    result["status"] = "PASS"
except Exception as exc:
    result["error"] = {"type": type(exc).__name__, "reason": str(exc)}
    raise
finally:
    for name in [
        "work-result.json",
        "agent-attempts.json",
        "regression-before.log",
        "regression-after.log",
        *[f"regression-attempt-{i}.log" for i in range(1, 4)],
    ]:
        if (workspace / name).exists():
            shutil.copyfile(workspace / name, evidence / name)
    if (workspace / TARGET).exists():
        shutil.copyfile(workspace / TARGET, evidence / "workspace-disk-execution-env.py")
    for name in ("improve.txt", "diff_errors.txt"):
        path = workspace / "agent-memory/.gpteng/memory/logs" / name
        if path.exists():
            shutil.copyfile(path, evidence / ("agent-" + name))
    result["finished_at"] = datetime.now(UTC).isoformat()
    (evidence / "baseline-result.json").write_text(json.dumps(result, indent=2) + "\n")
    if identity:
        docker.call(["rm", "--force", identity])
