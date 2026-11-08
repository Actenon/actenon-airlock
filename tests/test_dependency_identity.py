"""Acceptance identity v2 binds installed dependencies to the artifacts uv.lock pins (D8).

Identity v1 required each dependency's direct_url.json, so the frozen Gate 5/6 runner could not
identify a registry install at all. v2 must recognise the approved registry artifacts and refuse
anything else, and it must still bind git installs to the locked commit.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "dependency_identity", ROOT / "acceptance" / "dependency_identity.py"
)
ident = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ident)

VERSION = "1.0.0"
PYPI = ident.PYPI_FILES + "packages/"


def wheel(name: str, *, version: str = VERSION, extra: dict[str, bytes] | None = None) -> bytes:
    mod = name.replace("-", "_")
    info = f"{mod}-{version}.dist-info"
    files = {
        f"{mod}/__init__.py": f"NAME = {name!r}\n".encode(),
        f"{mod}/core.py": b"def run():\n    return 1\n",
        f"{info}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n".encode(),
        f"{info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        **(extra or {}),
    }
    rows = io.StringIO()
    writer = csv.writer(rows)
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([path, f"sha256={digest}", len(data)])
    writer.writerow([f"{info}/RECORD", "", ""])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
        archive.writestr(f"{info}/RECORD", rows.getvalue())
    return buf.getvalue()


def install(site: Path, blob: bytes, *, direct_url: dict | None = None) -> None:
    """What an installer does: unpack, then write RECORD over what it wrote, plus INSTALLER."""
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        archive.extractall(site)
        info = next(n.split("/")[0] for n in archive.namelist() if ".dist-info/" in n)
    (site / info / "INSTALLER").write_text("pip\n")
    if direct_url is not None:
        (site / info / "direct_url.json").write_text(json.dumps(direct_url))
    rewrite_record(site, info)


def rewrite_record(site: Path, info: str) -> None:
    rows = io.StringIO()
    writer = csv.writer(rows)
    for path in sorted(p for p in site.rglob("*") if p.is_file()):
        rel = path.relative_to(site).as_posix()
        if not (rel.startswith(info.split("-")[0] + "/") or rel.startswith(info + "/")):
            continue
        if rel == f"{info}/RECORD":
            continue
        data = path.read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([rel, f"sha256={digest}", len(data)])
    writer.writerow([f"{info}/RECORD", "", ""])
    (site / info / "RECORD").write_text(rows.getvalue())


class Env:
    """Four installed dependencies, a lock and an artifact store; tests change one thing."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.store = tmp / "store"
        self.store.mkdir()
        self.wheels = {name: wheel(name) for name in ident.NAMES}
        self.locked = dict(self.wheels)
        self.git: dict[str, str] = {}
        self.installed = dict(self.wheels)
        self.direct: dict[str, dict] = {}

    def lock(self) -> Path:
        blocks = []
        for name in ident.NAMES:
            if name in self.git:
                rev = self.git[name]
                source = f'{{ git = "https://github.com/Actenon/{name}?rev={rev}#{rev}" }}'
                blocks.append(
                    f'[[package]]\nname = "{name}"\nversion = "{VERSION}"\nsource = {source}\n'
                )
                continue
            blob = self.locked[name]
            digest = hashlib.sha256(blob).hexdigest()
            (self.store / f"{name}.whl").write_bytes(blob)
            blocks.append(
                f'[[package]]\nname = "{name}"\nversion = "{VERSION}"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
                f'wheels = [{{ url = "{PYPI}{digest}.whl", hash = "sha256:{digest}" }}]\n'
            )
        path = self.tmp / "uv.lock"
        path.write_text("version = 1\n\n" + "\n".join(blocks))
        return path

    def sites(self) -> dict[str, Path]:
        out = {}
        for name, blob in self.installed.items():
            site = self.tmp / "site" / name
            if not site.exists():
                site.mkdir(parents=True)
                install(site, blob, direct_url=self.direct.get(name))
            out[name] = site
        return out

    def distribution(self, name: str) -> importlib.metadata.Distribution:
        site = self.sites()[name]
        info = next(site.glob("*.dist-info"))
        return importlib.metadata.PathDistribution(info)

    def identify(self) -> dict:
        return ident.identify(self.lock(), store=self.store, distribution=self.distribution)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def test_registry_installs_are_bound_to_the_locked_wheels(env: Env) -> None:
    result = env.identify()
    for name in ident.NAMES:
        assert result[name]["install"] == "registry"
        assert result[name]["artifact_sha256"] == hashlib.sha256(env.wheels[name]).hexdigest()
        assert result[name]["version"] == VERSION


def test_identity_never_needs_direct_url_json(env: Env) -> None:
    env.sites()
    assert not list((env.tmp / "site").rglob("direct_url.json"))
    assert env.identify()["actenon-kernel"]["install"] == "registry"


def test_an_edited_installed_file_is_refused(env: Env) -> None:
    site = env.sites()["actenon-kernel"]
    (site / "actenon_kernel" / "core.py").write_text("def run():\n    return 'patched'\n")
    with pytest.raises(ident.IdentityError, match="does not match its RECORD"):
        env.identify()


def test_a_rewritten_record_cannot_hide_an_edit(env: Env) -> None:
    site = env.sites()["actenon-permit"]
    (site / "actenon_permit" / "core.py").write_text("def run():\n    return 'patched'\n")
    rewrite_record(site, f"actenon_permit-{VERSION}.dist-info")
    with pytest.raises(ident.IdentityError, match="not exactly one locked wheel"):
        env.identify()


def test_another_build_of_the_same_version_is_refused(env: Env) -> None:
    env.installed["actenon-scan"] = wheel(
        "actenon-scan", extra={"actenon_scan/shim.py": b"x = 1\n"}
    )
    with pytest.raises(ident.IdentityError, match="not exactly one locked wheel"):
        env.identify()


def test_another_version_is_refused(env: Env) -> None:
    env.installed["actenon-protocol"] = wheel("actenon-protocol", version="1.0.1")
    with pytest.raises(ident.IdentityError, match="is installed but"):
        env.identify()


def test_a_registry_lock_refuses_a_git_install(env: Env) -> None:
    env.direct["actenon-kernel"] = {
        "url": "https://github.com/Actenon/actenon-kernel",
        "vcs_info": {"vcs": "git", "commit_id": "1" * 40},
    }
    with pytest.raises(ident.IdentityError, match="installed from source"):
        env.identify()


def test_git_locks_still_bind_the_installed_commit(env: Env) -> None:
    commit = "2" * 40
    env.git["actenon-kernel"] = commit
    env.direct["actenon-kernel"] = {
        "url": "https://github.com/Actenon/actenon-kernel",
        "vcs_info": {"vcs": "git", "commit_id": commit},
    }
    assert env.identify()["actenon-kernel"] == {"install": "vcs", "commit": commit}
    env.git["actenon-kernel"] = "3" * 40
    with pytest.raises(ident.IdentityError, match="is locked at"):
        env.identify()


def test_a_git_lock_refuses_an_index_install(env: Env) -> None:
    env.git["actenon-scan"] = "4" * 40
    with pytest.raises(ident.IdentityError, match="installed from a package index"):
        env.identify()


def test_store_bytes_must_hash_to_the_lock_and_only_pypi_is_fetched(env: Env) -> None:
    lock = env.lock()
    for file in env.store.iterdir():
        file.write_bytes(b"not the locked wheel")
    text = lock.read_text().replace(PYPI, "https://mirror.example/")
    lock.write_text(text)
    with pytest.raises(ident.IdentityError, match="not on PyPI"):
        ident.identify(lock, store=env.store, distribution=env.distribution)


def test_an_unlocked_dependency_is_refused(env: Env) -> None:
    lock = env.lock()
    lock.write_text(lock.read_text().replace('name = "actenon-permit"', 'name = "actenon-other"'))
    with pytest.raises(ident.IdentityError, match="actenon-permit is not locked"):
        ident.identify(lock, store=env.store, distribution=env.distribution)


def test_a_real_pip_index_install_is_recognised(tmp_path: Path) -> None:
    """pip, resolving from an index-style source, writes no direct_url.json; v2 still binds it."""
    house = tmp_path / "wheelhouse"
    house.mkdir()
    blobs = {name: wheel(name) for name in ident.NAMES}
    for name, blob in blobs.items():
        (house / f"{name.replace('-', '_')}-{VERSION}-py3-none-any.whl").write_bytes(blob)
    site = tmp_path / "site"
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--no-index", "--no-deps",
         "--find-links", str(house), "--target", str(site),
         *(f"{n}=={VERSION}" for n in ident.NAMES)],
        check=True, capture_output=True,
    )  # fmt: skip
    lines = ["version = 1\n"]
    for name, blob in blobs.items():
        digest = hashlib.sha256(blob).hexdigest()
        lines.append(
            f'[[package]]\nname = "{name}"\nversion = "{VERSION}"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            f'wheels = [{{ url = "{PYPI}{digest}.whl", hash = "sha256:{digest}" }}]\n'
        )
    lock = tmp_path / "uv.lock"
    lock.write_text("\n".join(lines))

    def distribution(name: str) -> importlib.metadata.Distribution:
        found = [
            d
            for d in importlib.metadata.distributions(path=[str(site)])
            if d.metadata["Name"] == name
        ]
        assert len(found) == 1
        return found[0]

    result = ident.identify(lock, store=house, distribution=distribution)
    assert {r["install"] for r in result.values()} == {"registry"}


def test_this_environment_is_exactly_what_its_lock_pins() -> None:
    """In CI's git path and in the registry rehearsal alike, the runner's identity must hold."""
    result = ident.identify(ROOT / "uv.lock")
    assert set(result) == set(ident.NAMES)
