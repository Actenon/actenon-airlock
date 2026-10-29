"""
ACTENON FIELD TEST 5: THE ONE EXACT CHANGE CHALLENGE
Comprehensive, independent evaluation harness.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from actenon_airlock import broker as broker_module
from actenon_airlock.cli import main as airlock_cli
from actenon_airlock.common import AirlockError, digest
from actenon_airlock.github_consequence import (
    MAX_OBSERVATION_BYTES,
    ReviewedGitHubCreate,
    project_create,
)
from actenon_airlock.github_observer import observe_github
from actenon_airlock.github_runtime import PROFILE_SCHEMA, effect_descriptor, scan_power
from actenon_airlock.manifest import discover
from actenon_airlock.protected import ProtectedBroker
from actenon_airlock.reconciliation import (
    apply_reconciliation,
    load_operator_key,
    operator_identity,
    prepare_reconciliation,
)
from actenon_airlock.state import State
from actenon_protocol.effects import effect_identity

# --- Synthetic Constants (No real GitHub, no real credentials) ---
APPROVED_CONTENT = b'{"audit_version": "1.0", "approved_by": "secops", "status": "verified"}\n'
PARENT_SHA = "1" * 40
COMMITTED_SHA = "2" * 40
SYNTHETIC_GITHUB_SECRET = "github_pat_SYNTHETIC_SUPERVISOR_SECRET_776655_NEVER_LEAK"

@dataclass
class ProviderFixtureState:
    repo_id: int = 78901
    repo_node_id: str = "R_disposable_78901"
    owner: str = "acme"
    repo: str = "disposable-target"
    branch: str = "main"
    path: str = "security/audit_manifest.json"
    message: str = "deploy approved audit manifest"
    expected_parent_sha: str = PARENT_SHA
    current_head_sha: str = PARENT_SHA
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

        # --- Readback Fault Simulation ---
        if self.state.fault_on_readback and method == "GET":
            fault = self.state.fault_on_readback
            if fault == "timeout":
                raise httpx.ReadTimeout("Simulated readback timeout", request=request)
            if fault == "404":
                return httpx.Response(404, json={"message": "Resource Not Found"})
            if fault == "mismatched_parent" and url == branch_commit_url:
                return httpx.Response(200, json={
                    "sha": s.current_head_sha,
                    "url": f"{repo_url}/commits/{s.current_head_sha}",
                    "commit": {"message": s.message},
                    "parents": [{"sha": "f" * 40}],  # Wrong parent
                    "files": [{"filename": s.path, "status": "added", "sha": "e" * 40}],
                })
            if fault == "mismatched_content" and url.startswith(contents_url):
                return httpx.Response(200, json={
                    "type": "file",
                    "path": s.path,
                    "name": Path(s.path).name,
                    "encoding": "base64",
                    "content": base64.b64encode(b"MISMATCHED_UNAPPROVED_CONTENT").decode() + "\n",
                    "size": len(b"MISMATCHED_UNAPPROVED_CONTENT"),
                    "sha": "0" * 40,
                })

        # --- Standard GitHub API Behavior ---
        # 1. GET repository identity
        if method == "GET" and url == repo_url:
            return httpx.Response(200, json={
                "id": s.repo_id,
                "node_id": s.repo_node_id,
                "full_name": f"{s.owner}/{s.repo}",
                "url": repo_url,
            })

        # 2. GET branch ref (preflight)
        if method == "GET" and url == branch_ref_url:
            return httpx.Response(200, json={
                "ref": f"refs/heads/{s.branch}",
                "object": {"type": "commit", "sha": s.current_head_sha},
            })

        # 3. GET branch commit (readback)
        if method == "GET" and url == branch_commit_url:
            file_bytes = s.files.get(s.path, b"")
            blob_sha = hashlib.sha1(b"blob " + str(len(file_bytes)).encode() + b"\0" + file_bytes).hexdigest()
            return httpx.Response(200, json={
                "sha": s.current_head_sha,
                "url": f"{repo_url}/commits/{s.current_head_sha}",
                "commit": {"message": s.message},
                "parents": [{"sha": s.expected_parent_sha}],
                "files": [{"filename": s.path, "status": "added", "sha": blob_sha}],
            })

        # 4. GET contents check (preflight: must be 404 at parent commit)
        if method == "GET" and url == contents_at_parent and s.path not in s.files:
            return httpx.Response(404, json={"message": "Not Found"})

        # 5. GET contents check (readback: returns committed content at new head)
        if method == "GET" and (url == contents_at_head or url.startswith(contents_url)):
            if s.path in s.files:
                file_bytes = s.files[s.path]
                blob_sha = hashlib.sha1(b"blob " + str(len(file_bytes)).encode() + b"\0" + file_bytes).hexdigest()
                return httpx.Response(200, json={
                    "type": "file",
                    "path": s.path,
                    "name": Path(s.path).name,
                    "encoding": "base64",
                    "content": base64.b64encode(file_bytes).decode() + "\n",
                    "size": len(file_bytes),
                    "sha": blob_sha,
                })
            return httpx.Response(404, json={"message": "Not Found"})

        # 6. PUT contents (the authorized mutation)
        if method == "PUT" and url == contents_url:
            data = json.loads(body_bytes.decode("utf-8"))
            content_decoded = base64.b64decode(data["content"])
            s.files[s.path] = content_decoded
            s.current_head_sha = COMMITTED_SHA
            blob_sha = hashlib.sha1(b"blob " + str(len(content_decoded)).encode() + b"\0" + content_decoded).hexdigest()

            # Uncertain execution simulation: commit mutation, but lose the HTTP response
            if s.lose_ack_on_put:
                raise httpx.ReadTimeout("Simulated dropped ACK on PUT response", request=request)

            return httpx.Response(201, json={
                "content": {"sha": blob_sha},
                "commit": {"sha": COMMITTED_SHA},
            })

        return httpx.Response(404, json={"error": f"Unhandled fixture route: {method} {url}"})

    @property
    def mutations(self) -> list[dict[str, Any]]:
        return [c for c in self.state.calls if c["method"] == "PUT"]

def build_review(state: ProviderFixtureState) -> ReviewedGitHubCreate:
    return ReviewedGitHubCreate(
        repo_id=state.repo_id,
        repo_node_id=state.repo_node_id,
        owner=state.owner,
        repo=state.repo,
        branch=state.branch,
        path=state.path,
        message=state.message,
        content_sha256=hashlib.sha256(APPROVED_CONTENT).hexdigest(),
        expected_parent_sha=state.expected_parent_sha,
    )

def make_profile_dict(review: ReviewedGitHubCreate) -> dict[str, Any]:
    return {
        "schema": PROFILE_SCHEMA,
        "exclusive_writer": True,
        "credential_name": "GITHUB_TOKEN",
        "review": asdict(review),
    }

def make_valid_creation_body(review: ReviewedGitHubCreate) -> bytes:
    payload = {
        "branch": review.branch,
        "message": review.message,
        "content": base64.b64encode(APPROVED_CONTENT).decode(),
    }
    return json.dumps(payload).encode("utf-8")

def make_protected_message(review: ReviewedGitHubCreate, **overrides) -> dict[str, Any]:
    msg = {
        "kind": "protected-http",
        "method": "PUT",
        "url": review.contents_url,
        "headers": {"Content-Type": "application/json"},
        "body": base64.b64encode(make_valid_creation_body(review)).decode(),
    }
    msg.update(overrides)
    return msg

print("Field Test 5 test harness module loaded successfully.")
