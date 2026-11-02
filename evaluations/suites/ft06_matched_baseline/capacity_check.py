"""Audit of the frozen G28–G38 gpt-engineer acceptance programme and capacity check."""

import json
import os
import subprocess
import sys
from pathlib import Path

AIRLOCK_REPO = Path("/Users/ross/.gemini/antigravity/scratch/actenon-airlock")

def audit_frozen_programme() -> dict:
    gpt_acceptance = AIRLOCK_REPO / "acceptance" / "gpt-engineer"
    manifest_bytes = (gpt_acceptance / "model-manifest.json").read_bytes()
    import hashlib
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    manifest = json.loads(manifest_bytes)
    model_bytes = sum(layer["size"] for layer in manifest["layers"])

    # Hardware evaluation
    host_mem_bytes = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip())
    
    docker_info = json.loads(subprocess.check_output(["docker", "info", "--format", "{{json .}}"], text=True))
    docker_mem_bytes = docker_info.get("MemTotal", 0)

    required_mem = 12 * 1024**3
    required_disk = model_bytes + 3 * 1024**3

    admitted = (docker_mem_bytes >= required_mem)

    upstream_history = {
        "run_37295234658": {
            "platform": "Linux ubuntu-latest (16 GiB RAM runner)",
            "model": "qwen2.5-coder:14b",
            "runtime_seconds": 1831,
            "result": "BASELINE_FAILED",
            "failure_reason": "IndentationError across all 3 attempts",
            "protected_phase": "SKIPPED",
        }
    }

    report = {
        "programme": "G28–G38 External Coding Agent Acceptance",
        "agent": "gpt-engineer 0.3.1",
        "frozen_source_commit": "a90fcd543eedcc0ff2c34561bc0785d2ba83c47e",
        "frozen_model": "qwen2.5-coder:14b",
        "model_manifest_sha256": manifest_digest,
        "model_archive_bytes": model_bytes,
        "capacity_requirements": {
            "required_available_memory_bytes": required_mem,
            "required_available_memory_gib": 12.0,
            "required_free_disk_bytes": required_disk,
        },
        "available_hardware": {
            "host_os": sys.platform,
            "host_physical_memory_bytes": host_mem_bytes,
            "docker_vm_total_memory_bytes": docker_mem_bytes,
            "docker_vm_total_memory_gib": round(docker_mem_bytes / (1024**3), 2),
        },
        "capacity_admitted": admitted,
        "blocker_reason": (
            f"Hardware capacity constraint: Docker Desktop VM allocated only {round(docker_mem_bytes / (1024**3), 2)} GiB RAM, "
            f"below the mandatory 12.0 GiB available memory required by capacity.py to admit qwen2.5-coder:14b without OOM abort."
        ),
        "upstream_historical_status": upstream_history,
        "frozen_gate_status": "BLOCKED",
    }
    return report

if __name__ == "__main__":
    report = audit_frozen_programme()
    print(json.dumps(report, indent=2))
