"""In-memory, independently auditable GitHub Contents API mock fixture for evaluations."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from actenon_airlock.github_consequence import (
    ReviewedGitHubCreate,
)

DEFAULT_PARENT_SHA = "1" * 40
DEFAULT_COMMITTED_SHA = "2" * 40


@dataclass
class ProviderFixtureState:
    repo_id: int = 78901
    repo_node_id: str = "R_disposable_78901"
    owner: str = "acme"
    repo: str = "disposable-target"
    branch: str = "main"
    path: str = "security/audit_manifest.json"
    message: str = "deploy approved audit manifest"
    expected_parent_sha: str = DEFAULT_PARENT_SHA
    current_head_sha: str = DEFAULT_PARENT_SHA
    files: dict[str, bytes] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)
    lose_ack_on_put: bool = False
    fault_on_readback: str | None = None


class GitHubContentsProviderFixture:
    """In-memory, independently auditable GitHub Contents API mock fixture."""

    def __init__(self, state: ProviderFixtureState):
        self.state = state

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        method = request.method
        auth = request.headers.get("authorization", "")
        body_bytes = request.content
        call_record = {
            "method": method,
            "url": url,
            "auth_received": auth[:25] + "..." if auth else None,
            "body_sha256": hashlib.sha256(body_bytes).hexdigest() if body_bytes else None,
            "body_len": len(body_bytes),
        }
        self.state.calls.append(call_record)

        s = self.state
        repo_url = f"https://api.github.com/repos/{s.owner}/{s.repo}"
        branch_ref_url = f"{repo_url}/git/ref/heads/{s.branch}"
        branch_commit_url = f"{repo_url}/commits/{s.branch}"
        contents_url = f"{repo_url}/contents/{s.path}"
        contents_at_parent = f"{contents_url}?ref={s.expected_parent_sha}"
        contents_at_head = f"{contents_url}?ref={s.current_head_sha}"

        # 1. Fault simulation for readback
        if self.state.fault_on_readback and method == "GET":
            fault = self.state.fault_on_readback
            if fault == "timeout":
                raise httpx.ReadTimeout("Simulated readback timeout", request=request)
            if fault == "404":
                return httpx.Response(404, json={"message": "Resource Not Found"})
            if fault == "mismatched_parent" and url == branch_commit_url:
                return httpx.Response(
                    200,
                    json={
                        "sha": s.current_head_sha,
                        "url": f"{repo_url}/commits/{s.current_head_sha}",
                        "commit": {"message": s.message},
                        "parents": [{"sha": "f" * 40}],
                        "files": [{"filename": s.path, "status": "added", "sha": "e" * 40}],
                    },
                )
            if fault == "mismatched_content" and url.startswith(contents_url):
                return httpx.Response(
                    200,
                    json={
                        "type": "file",
                        "path": s.path,
                        "name": Path(s.path).name,
                        "encoding": "base64",
                        "content": base64.b64encode(b"MISMATCHED_UNAPPROVED_CONTENT").decode()
                        + "\n",
                        "size": len(b"MISMATCHED_UNAPPROVED_CONTENT"),
                        "sha": "0" * 40,
                    },
                )

        # 2. GET repository identity
        if method == "GET" and url == repo_url:
            return httpx.Response(
                200,
                json={
                    "id": s.repo_id,
                    "node_id": s.repo_node_id,
                    "full_name": f"{s.owner}/{s.repo}",
                    "url": repo_url,
                },
            )

        # 3. GET branch ref (preflight)
        if method == "GET" and url == branch_ref_url:
            return httpx.Response(
                200,
                json={
                    "ref": f"refs/heads/{s.branch}",
                    "object": {"type": "commit", "sha": s.current_head_sha},
                },
            )

        # 4. GET branch commit (readback)
        if method == "GET" and url == branch_commit_url:
            file_bytes = s.files.get(s.path, b"")
            blob_sha = hashlib.sha1(
                b"blob " + str(len(file_bytes)).encode() + b"\0" + file_bytes
            ).hexdigest()
            return httpx.Response(
                200,
                json={
                    "sha": s.current_head_sha,
                    "url": f"{repo_url}/commits/{s.current_head_sha}",
                    "commit": {"message": s.message},
                    "parents": [{"sha": s.expected_parent_sha}],
                    "files": [{"filename": s.path, "status": "added", "sha": blob_sha}],
                },
            )

        # 5. GET contents check (preflight: must be 404 at parent commit)
        if method == "GET" and url == contents_at_parent and s.path not in s.files:
            return httpx.Response(404, json={"message": "Not Found"})

        # 6. GET contents check (readback)
        if method == "GET" and (url == contents_at_head or url.startswith(contents_url)):
            if s.path in s.files:
                file_bytes = s.files[s.path]
                blob_sha = hashlib.sha1(
                    b"blob " + str(len(file_bytes)).encode() + b"\0" + file_bytes
                ).hexdigest()
                return httpx.Response(
                    200,
                    json={
                        "type": "file",
                        "path": s.path,
                        "name": Path(s.path).name,
                        "encoding": "base64",
                        "content": base64.b64encode(file_bytes).decode() + "\n",
                        "size": len(file_bytes),
                        "sha": blob_sha,
                    },
                )
            return httpx.Response(404, json={"message": "Not Found"})

        # 7. PUT contents (the mutation)
        if method == "PUT" and url == contents_url:
            data = json.loads(body_bytes.decode("utf-8"))
            content_decoded = base64.b64decode(data["content"])
            s.files[s.path] = content_decoded
            s.current_head_sha = DEFAULT_COMMITTED_SHA
            blob_sha = hashlib.sha1(
                b"blob " + str(len(content_decoded)).encode() + b"\0" + content_decoded
            ).hexdigest()

            # Uncertain execution simulation: commit mutation, but lose HTTP ACK
            if s.lose_ack_on_put:
                raise httpx.ReadTimeout("Simulated dropped ACK on PUT response", request=request)

            return httpx.Response(
                201,
                json={
                    "content": {
                        "name": Path(s.path).name,
                        "path": s.path,
                        "sha": blob_sha,
                        "size": len(content_decoded),
                        "type": "file",
                    },
                    "commit": {
                        "sha": DEFAULT_COMMITTED_SHA,
                        "parents": [{"sha": s.expected_parent_sha}],
                        "message": s.message,
                    },
                },
            )

        return httpx.Response(404, json={"message": f"Unhandled mock route: {method} {url}"})


def build_reviewed_create(
    owner: str,
    repo: str,
    branch: str,
    path: str,
    content_bytes: bytes,
    commit_message: str,
    expected_parent_commit: str,
    repo_id: int = 78901,
    repo_node_id: str = "R_disposable_78901",
) -> ReviewedGitHubCreate:
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()
    return ReviewedGitHubCreate(
        repo_id=repo_id,
        repo_node_id=repo_node_id,
        owner=owner,
        repo=repo,
        branch=branch,
        path=path,
        message=commit_message,
        content_sha256=content_sha256,
        expected_parent_sha=expected_parent_commit,
    )
