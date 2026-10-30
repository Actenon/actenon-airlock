"""A disposable, stateful synthetic GitHub Contents provider. It is not GitHub.

Used only by an explicit `--synthetic-provider FILE` option, which replaces the
HTTP transport in-process so nothing can reach a network or a real account. It
keeps its own state and request log in that file, separate from Airlock's state,
so the log independently shows which requests actually arrived.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx

from .common import AirlockError

SCHEMA = "actenon-airlock/synthetic-github/v1"
TOKEN = "synthetic-github-token-not-a-real-credential"


def _blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324


def create_provider(path: Path, *, owner="acme", repo="disposable", branch="review") -> dict:
    """Create a one-commit repository in `path`; refuse to overwrite an existing one."""
    root = hashlib.sha1(f"{owner}/{repo}/{branch}".encode()).hexdigest()  # noqa: S324
    state = {
        "schema": SCHEMA,
        "notice": "SYNTHETIC PROVIDER: not GitHub; no account or network involved",
        "repository": {"id": 4242, "node_id": "R_synthetic", "owner": owner, "name": repo},
        "branch": branch,
        "head": root,
        "commits": {root: {"parent": None, "message": "initial", "files": []}},
        "files": {},
        "lose_next_acknowledgement": False,
        "requests": [],
    }
    with path.open("x", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2)
    return state


class SyntheticGitHub:
    """httpx.MockTransport handler; every request is logged before it is answered."""

    def __init__(self, path: Path):
        self.path = path
        try:
            self.state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AirlockError(f"Synthetic provider file is unreadable: {path}") from exc
        if self.state.get("schema") != SCHEMA:
            raise AirlockError("Not a synthetic provider file")

    def _save(self) -> None:
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)

    @property
    def _base(self) -> str:
        repository = self.state["repository"]
        return f"/repos/{repository['owner']}/{repository['name']}"

    def _commit_json(self, sha: str) -> dict:
        commit = self.state["commits"][sha]
        return {
            "sha": sha,
            "url": f"https://api.github.com{self._base}/commits/{sha}",
            "commit": {"message": commit["message"]},
            "parents": [{"sha": commit["parent"]}] if commit["parent"] else [],
            "files": commit["files"],
        }

    def _contents_json(self, path: str, entry: dict) -> dict:
        data = base64.b64decode(entry["content"])
        return {
            "type": "file",
            "path": path,
            "name": path.rsplit("/", 1)[-1],
            "encoding": "base64",
            "content": entry["content"],
            "sha": _blob_sha(data),
            "size": len(data),
        }

    def _visible_at(self, path: str, sha: str) -> dict | None:
        """The file as of commit `sha`: only commits reachable from it count."""
        reachable, current = set(), sha
        while current:
            reachable.add(current)
            current = self.state["commits"][current]["parent"]
        entry = self.state["files"].get(path)
        return entry if entry and entry["commit"] in reachable else None

    def _create(self, path: str, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if path in self.state["files"]:
            return httpx.Response(422, json={"message": "sha wasn't supplied"})
        if body.get("branch") != self.state["branch"]:
            return httpx.Response(404, json={"message": "Branch not found"})
        data = base64.b64decode(body["content"], validate=True)
        parent = self.state["head"]
        material = f"{parent}{path}{body['message']}{_blob_sha(data)}".encode()
        sha = hashlib.sha1(material).hexdigest()  # noqa: S324
        self.state["commits"][sha] = {
            "parent": parent,
            "message": body["message"],
            "files": [{"filename": path, "status": "added", "sha": _blob_sha(data)}],
        }
        self.state["files"][path] = {"content": body["content"], "commit": sha}
        self.state["head"] = sha
        return httpx.Response(
            201, json={"content": {"sha": _blob_sha(data)}, "commit": {"sha": sha}}
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        path = unquote(url.path)
        authorized = request.headers.get("authorization") == "Bearer " + TOKEN
        self.state["requests"].append(
            {
                "method": request.method,
                "url": str(request.url),
                "authorized": authorized,
                "body_sha256": hashlib.sha256(request.content).hexdigest(),
            }
        )
        try:
            if url.hostname != "api.github.com" or not authorized:
                return httpx.Response(401, json={"message": "Bad credentials"})
            return self._route(request, path, url.query)
        finally:
            self._save()

    def _route(self, request: httpx.Request, path: str, query: str) -> httpx.Response:
        base, repository = self._base, self.state["repository"]
        contents = base + "/contents/"
        if request.method == "GET" and path == base:
            name = f"{repository['owner']}/{repository['name']}"
            return httpx.Response(
                200,
                json={
                    "id": repository["id"],
                    "node_id": repository["node_id"],
                    "full_name": name,
                    "url": f"https://api.github.com{base}",
                },
            )
        if request.method == "GET" and path == f"{base}/git/ref/heads/{self.state['branch']}":
            return httpx.Response(
                200,
                json={
                    "ref": "refs/heads/" + self.state["branch"],
                    "object": {"type": "commit", "sha": self.state["head"]},
                },
            )
        if request.method == "GET" and path == f"{base}/commits/{self.state['branch']}":
            return httpx.Response(200, json=self._commit_json(self.state["head"]))
        if request.method == "GET" and path.startswith(contents):
            name, ref = path[len(contents) :], query.removeprefix("ref=")
            entry = self._visible_at(name, ref) if ref in self.state["commits"] else None
            if entry is None:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json=self._contents_json(name, entry))
        if request.method == "PUT" and path.startswith(contents):
            response = self._create(path[len(contents) :], request)
            if response.status_code == 201 and self.state["lose_next_acknowledgement"]:
                self.state["lose_next_acknowledgement"] = False
                raise httpx.ReadTimeout("synthetic acknowledgement lost", request=request)
            return response
        return httpx.Response(404, json={"message": "Not Found"})


def synthetic_client(path: Path) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(SyntheticGitHub(path)), follow_redirects=False
    )
