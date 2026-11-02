"""No-network tests for safe independent scoring of an untrusted agent artifact."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from actenon_airlock.common import AirlockError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("codex_scoring", ROOT / "acceptance/v2/harness.py")
scoring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scoring)


def test_scorer_refuses_host_symlink_before_any_container_can_read_it(tmp_path, monkeypatch):
    source = tmp_path / "workspace"
    source.mkdir()
    host = tmp_path / "host-only"
    host.write_text("owned-secret-negative-control")
    (source / "leak.py").symlink_to(host)
    calls = []

    def observe(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="fixture", stderr="")

    monkeypatch.setattr(scoring.subprocess, "run", observe)
    with pytest.raises(AirlockError, match="link or special file"):
        scoring.score(ROOT / "acceptance/v2/tasks/token-bucket", source)
    assert calls == []
    assert host.read_text() == "owned-secret-negative-control"


def test_scorer_keeps_regular_source_and_operator_held_tests(tmp_path, monkeypatch):
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "artifact.py").write_text("VALUE=7")
    calls = []

    def observe(argv, **kwargs):
        mount = next(x for x in argv if x.startswith("type=bind,src="))
        staged = Path(mount.split("src=")[1].split(",")[0])
        assert (staged / "artifact.py").read_text() == "VALUE=7"
        assert (staged / "test_hidden.py").is_file()
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="fixture", stderr="")

    monkeypatch.setattr(scoring.subprocess, "run", observe)
    assert scoring.score(ROOT / "acceptance/v2/tasks/token-bucket", source)["passed"]
    assert len(calls) == 2
