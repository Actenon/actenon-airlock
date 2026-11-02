"""Trusted image build only: verify an official archive, install its unchanged binary."""

import hashlib
import io
import json
import platform
import tarfile
import urllib.request
from pathlib import Path

provenance = json.loads(Path("/opt/codex-upstream.json").read_text())
architecture = {"aarch64": "aarch64", "x86_64": "x86_64"}[platform.machine()]
name = f"codex-{architecture}-unknown-linux-musl"
asset = next(a for a in provenance["assets"] if a["name"] == name + ".tar.gz")
with urllib.request.urlopen(asset["browser_download_url"], timeout=120) as response:
    archive = response.read()
if "sha256:" + hashlib.sha256(archive).hexdigest() != asset["digest"]:
    raise ValueError("Official Codex archive digest mismatch")
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
    member = next(m for m in bundle.getmembers() if m.name == name and m.isfile())
    binary = bundle.extractfile(member).read()
path = Path("/usr/local/bin/codex")
path.write_bytes(binary)
path.chmod(0o555)
provenance.update(binary_sha256=hashlib.sha256(binary).hexdigest(), architecture=architecture)
Path("/opt/codex-upstream.json").write_text(json.dumps(provenance, indent=2) + "\n")
