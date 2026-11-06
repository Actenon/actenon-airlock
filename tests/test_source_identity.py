import importlib.util
import subprocess
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "source_identity", Path(__file__).resolve().parents[1] / "scripts/source_identity.py"
)
source_identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source_identity)


@pytest.mark.parametrize("change", ["none", "bytes", "extra", "missing", "symlink", "pycache"])
def test_source_identity_detects_runtime_drift_without_importing_package(tmp_path, change):
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    package = tmp_path / "src/actenon_airlock"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_text("raise RuntimeError('Must never import runtime for identity')\n")
    git("init")
    git("add", "src")
    git(
        "-c",
        "user.name=Synthetic",
        "-c",
        "user.email=synthetic@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    original = source_identity.identity(tmp_path)
    if change == "bytes":
        source.write_text("changed")
    elif change == "extra":
        (package / "extra.py").write_text("extra")
    elif change == "missing":
        source.unlink()
    elif change == "symlink":
        content = source.read_bytes()
        source.unlink()
        target = tmp_path / "target.py"
        target.write_bytes(content)
        source.symlink_to(target)
    elif change == "pycache":
        (package / "__pycache__").mkdir()
        (package / "__pycache__/ignored.pyc").write_bytes(b"synthetic")
    if change in {"none", "pycache"}:
        assert source_identity.identity(tmp_path) == original
    else:
        with pytest.raises(ValueError, match="Runtime source"):
            source_identity.identity(tmp_path)
    assert (
        source_identity.identity(tmp_path, git_only=True)["source_digest"]
        == original["source_digest"]
    )
