"""Record actual disposable runner capacity before downloading the pinned model."""

import argparse
import hashlib
import json
import os
import platform
import shutil
from datetime import UTC, datetime
from pathlib import Path

from configuration import MODEL, MODEL_DIGEST

parser = argparse.ArgumentParser()
parser.add_argument("--evidence", type=Path, required=True)
parser.add_argument("--model-directory", type=Path, required=True)
args = parser.parse_args()
manifest_bytes = Path(__file__).with_name("model-manifest.json").read_bytes()
assert hashlib.sha256(manifest_bytes).hexdigest() == MODEL_DIGEST
manifest = json.loads(manifest_bytes)
model_bytes = sum(layer["size"] for layer in manifest["layers"])
memory = {}
for line in Path("/proc/meminfo").read_text().splitlines():
    key, value = line.split(":", 1)
    if key in {"MemTotal", "MemAvailable"}:
        memory[key] = int(value.split()[0]) * 1024
space = shutil.disk_usage(args.model_directory)
# Actual previous runner evidence: 15.6 GiB total / 14.3 GiB available.
# The 14b weights occupy 8.37 GiB. Reserve roughly 3.6 GiB for context,
# compute buffers and the unchanged 1-GiB agent, then check actual admission.
required_memory = 12 * 1024**3
required_disk = model_bytes + 3 * 1024**3
result = {
    "recorded_at": datetime.now(UTC).isoformat(),
    "platform": platform.platform(),
    "cpu_count": os.cpu_count(),
    "model": MODEL,
    "model_manifest_sha256": MODEL_DIGEST,
    "model_archive_bytes": model_bytes,
    "memory": memory,
    "disk": {"total_bytes": space.total, "free_bytes": space.free},
    "required_available_memory_bytes": required_memory,
    "required_free_disk_bytes": required_disk,
    "admitted": memory["MemAvailable"] >= required_memory and space.free >= required_disk,
    "scope": "Capacity admission only; successful model execution is still required",
}
with args.evidence.open("x") as stream:
    json.dump(result, stream, indent=2)
    stream.write("\n")
assert result["admitted"], "Insufficient actual runner capacity for the frozen 14b candidate"
print(json.dumps(result, indent=2))
