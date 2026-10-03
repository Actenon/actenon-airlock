import json
import subprocess
import sys

import pytest


def run(state):
    return subprocess.run(
        [sys.executable, "-m", "actenon_airlock.cli", "run", "--path", str(state.root)],
        capture_output=True,
        text=True,
        timeout=40,
    )


@pytest.mark.parametrize(
    "source",
    [
        'import requests\nassert requests.post("{url}/a", data="hello").json()["ok"]\n',
        'import httpx\nassert httpx.post("{url}/a", content="hello").json()["ok"]\n',
        'import urllib.request\nr=urllib.request.urlopen(urllib.request.Request("{url}/a", data=b"hello"))\nassert r.status == 200\n',
        'import httpx, asyncio\nasync def go():\n async with httpx.AsyncClient() as c:\n  r=await c.post("{url}/a", content="hello")\n  assert r.json()["ok"]\nasyncio.run(go())\n',
    ],
)
def test_real_client_runs_without_application_changes(project, server, source):
    url, calls = server
    state = project(source.format(url=url))
    result = run(state)
    assert result.returncode == 0, result.stderr
    assert len(calls) == 1 and calls[0][0] == "/a"
    assert "AIRLOCK ALLOW" in result.stderr


def test_new_power_is_blocked_even_if_agent_catches_error(project, server):
    url, calls = server
    state = project(f'import requests\nrequests.post("{url}/a")\n')
    (state.root / "main.py").write_text(
        f'import requests\ntry:\n requests.delete("{url}/b")\nexcept Exception:\n pass\n'
    )
    result = run(state)
    assert result.returncode == 3 and calls == []
    assert "AIRLOCK DENY" in result.stderr


@pytest.mark.parametrize(
    "source",
    [
        'import socket\nsocket.socket().connect(("127.0.0.1", {port}))\n',
        'import os\nos.system("true")\n',
        'import os\nfd=os.open("output.txt", os.O_WRONLY|os.O_CREAT)\n',
    ],
)
def test_unscanned_bypass_is_blocked_at_runtime(project, server, source):
    url, calls = server
    state = project(source.format(port=int(url.rsplit(":", 1)[1])))
    result = run(state)
    assert result.returncode != 0
    assert calls == []
    assert not (state.root / "output.txt").exists()


def test_child_cannot_read_approval_key(project):
    # Dynamic file read bypasses static write discovery but remains denied.
    state = project(
        'from pathlib import Path\nprint(Path(".airlock/local/key.json").read_text())\n'
    )
    result = run(state)
    assert result.returncode == 3
    assert "private_key" not in result.stdout


def test_unknown_environment_secrets_are_not_inherited(project, monkeypatch):
    monkeypatch.setenv("UNLISTED_SECRET", "do-not-inherit")
    state = project('import os\nassert "UNLISTED_SECRET" not in os.environ\n')
    result = run(state)
    assert result.returncode == 0, result.stderr


def test_pygithub_requester_uses_requests_broker(project, monkeypatch):
    # No real GitHub write: unapproved repo deletion must deny before transport.
    monkeypatch.setenv("GITHUB_TOKEN", "not-a-real-token")
    state = project("from github import Github\n# empty approved powers\n")
    (state.root / "main.py").write_text(
        "import os\nfrom github import Github\n"
        'Github(os.environ["GITHUB_TOKEN"]).get_repo("acme/project", lazy=True).delete()\n'
    )
    result = run(state)
    assert result.returncode == 3
    rows = [json.loads(s) for s in (state.local / "receipts.jsonl").read_text().splitlines()]
    assert any(row["action"] == "github.repo.delete" and row["decision"] == "DENY" for row in rows)
