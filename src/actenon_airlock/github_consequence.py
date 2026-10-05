"""Trusted-host GitHub Contents create-only projection and observation validation.

Pure functions: no network, credentials, grant issuance, retries or settlement.
A COMMITTED result means anchored provider state was observed under the caller's
exclusive-writer assumption; it does not prove which process caused that state.
The Contents API cannot compare-and-swap a reviewed parent commit. The host must
preflight, prevent redirects, use a repository-scoped credential, and preserve
that deployment assumption across dispatch/readback. Otherwise remain AMBIGUOUS.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import quote

from actenon_protocol.canonicalisation import canonicalize_bytes, parse_strict
from actenon_protocol.effects import EFFECT_PROFILE
from actenon_scan.authority import ResourceState, classify_http

MAX_CONTENT_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 128 * 1024
MAX_OBSERVATION_BYTES = 1024 * 1024
PROFILE = "github-contents-create/v1"
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+\Z")


class GitHubConsequenceError(ValueError):
    """Unsupported or unconfirmed reviewed GitHub consequence."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise GitHubConsequenceError(reason)


def _text(value: object, limit: int) -> bool:
    try:
        return type(value) is str and bool(value) and len(value.encode("utf-8")) <= limit
    except UnicodeError:
        return False


def _sha(value: object, pattern: re.Pattern) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _path(value: str, *, branch: bool = False) -> bool:
    if not _text(value, 240) or value.startswith("/") or value.endswith("/"):
        return False
    segments = value.split("/")
    if any(
        not _SEGMENT.fullmatch(p) or p in {".", ".."} or p.casefold() == ".git" for p in segments
    ):
        return False
    if branch:
        return not (
            value == "@"
            or ".." in value
            or value.endswith(".")
            or any(p.startswith(".") or p.endswith(".lock") for p in segments)
            or _SHA1.fullmatch(value)
            or value.startswith("refs/")
        )
    return not (
        len(segments) >= 2 and [p.casefold() for p in segments[:2]] == [".github", "workflows"]
    )


@dataclass(frozen=True)
class ReviewedGitHubCreate:
    """Host-reviewed identity; never constructed from an agent's approval claim."""

    repo_id: int
    repo_node_id: str
    owner: str
    repo: str
    branch: str
    path: str
    message: str
    content_sha256: str
    expected_parent_sha: str

    def __post_init__(self) -> None:
        _require(type(self.repo_id) is int and 0 < self.repo_id < 2**63, "invalid repository id")
        _require(
            _text(self.repo_node_id, 256)
            and re.fullmatch(r"[A-Za-z0-9_+=/-]+", self.repo_node_id) is not None,
            "invalid repository node id",
        )
        _require(
            type(self.owner) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", self.owner) is not None,
            "unsupported repository owner",
        )
        _require(
            type(self.repo) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", self.repo) is not None
            and not self.repo.endswith(".git"),
            "unsupported repository name",
        )
        object.__setattr__(self, "owner", self.owner.lower())
        object.__setattr__(self, "repo", self.repo.lower())
        _require(_path(self.branch, branch=True), "unsupported branch")
        _require(_path(self.path), "unsupported path")
        _require(
            _text(self.message, 4096)
            and self.message == self.message.strip()
            and "\0" not in self.message
            and "\r" not in self.message,
            "unsupported commit message",
        )
        _require(_sha(self.content_sha256, _SHA256), "invalid reviewed content digest")
        _require(_sha(self.expected_parent_sha, _SHA1), "invalid reviewed parent commit")
        authority = classify_http("PUT", self.contents_url)
        _require(
            authority.state == ResourceState.RESOLVED
            and authority.action == "github.contents.write"
            and authority.resource == self.resource,
            "Scan does not resolve the supported Contents power",
        )

    @property
    def repository_url(self) -> str:
        return f"https://api.github.com/repos/{self.owner}/{self.repo}"

    @property
    def contents_url(self) -> str:
        return self.repository_url + "/contents/" + self.path

    @property
    def branch_ref_url(self) -> str:
        return self.repository_url + "/git/ref/heads/" + quote(self.branch, safe="")

    @property
    def branch_commit_url(self) -> str:
        return self.repository_url + "/commits/" + quote(self.branch, safe="")

    @property
    def resource(self) -> str:
        return f"github.com/{self.owner}/{self.repo}"

    def contents_at(self, commit_sha: str) -> str:
        _require(_sha(commit_sha, _SHA1), "readback requires a full commit SHA")
        return self.contents_url + "?ref=" + commit_sha

    @property
    def projection(self) -> dict:
        """Finite authority can be computed before receiving any agent body.

        Parent SHA is a reviewed observation anchor, not a resettable identity
        input. No trace/header/session/proof/grant identifier enters this key.
        """
        return {
            "operation": PROFILE,
            "repository": {
                "id": self.repo_id,
                "node_id": self.repo_node_id,
                "full_name": f"{self.owner}/{self.repo}",
            },
            "branch": self.branch,
            "path": self.path,
            "content_sha256": self.content_sha256,
            "message": self.message,
        }

    def effect_descriptor(self, namespace: str) -> dict:
        """Namespace must come from the durable resource owner's host state."""
        return {
            "profile": EFFECT_PROFILE,
            "namespace": namespace,
            "kind": "semantic",
            "action_type": "github.contents.write",
            "target": {"type": "http", "id": self.contents_url},
            "semantic_key": self.projection,
        }


@dataclass(frozen=True)
class GitHubCreateRequest:
    review: ReviewedGitHubCreate
    body: bytes = field(repr=False)
    git_blob_sha1: str
    content_size: int
    action: str = "github.contents.write"

    @property
    def resource(self) -> str:
        return self.review.resource

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def effect_descriptor(self, namespace: str) -> dict:
        return self.review.effect_descriptor(namespace)


def _json_body(raw: bytes, limit: int) -> dict:
    _require(type(raw) is bytes and len(raw) <= limit, "body is not bounded bytes")
    try:
        value = parse_strict(raw.decode("utf-8", errors="strict"))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise GitHubConsequenceError("invalid strict JSON body") from exc
    _require(type(value) is dict, "JSON body must be an object")
    return value


def _decode_content(value: object, *, response: bool = False) -> bytes:
    _require(type(value) is str, "content must be base64 text")
    # GitHub documents newline-wrapped base64 readback. Requests have one exact
    # canonical spelling; responses may include only CR/LF wrapping.
    encoded = value.replace("\r", "").replace("\n", "") if response else value
    _require(len(encoded) <= 4 * ((MAX_CONTENT_BYTES + 2) // 3), "content exceeds supported bound")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GitHubConsequenceError("invalid base64 content") from exc
    _require(
        len(content) <= MAX_CONTENT_BYTES and base64.b64encode(content).decode("ascii") == encoded,
        "noncanonical or oversized base64",
    )
    return content


def _blob_sha(content: bytes) -> str:
    # Git's SHA-1 object name is checked alongside authoritative content SHA256.
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content, usedforsecurity=False
    ).hexdigest()


def project_create(
    method: str, url: str, raw_body: bytes, review: ReviewedGitHubCreate
) -> GitHubCreateRequest:
    _require(
        method == "PUT" and url == review.contents_url,
        "request is outside the exact reviewed Contents endpoint",
    )
    value = _json_body(raw_body, MAX_REQUEST_BYTES)
    _require(
        set(value) == {"message", "content", "branch"},
        "only message/content/branch are supported; updates are forbidden",
    )
    _require(
        value["message"] == review.message
        and type(value["message"]) is str
        and value["branch"] == review.branch
        and type(value["branch"]) is str,
        "request differs from reviewed message or branch",
    )
    content = _decode_content(value["content"])
    _require(
        hashlib.sha256(content).hexdigest() == review.content_sha256,
        "content differs from reviewed digest",
    )
    # These exact bytes must be used for authority, proof hashing and dispatch.
    body = canonicalize_bytes(value)
    return GitHubCreateRequest(review, body, _blob_sha(content), len(content))


@dataclass(frozen=True)
class HostObservation:
    """Only the trusted no-redirect host transport may supply this object."""

    url: str
    status: int
    body: bytes = field(repr=False)
    redirected: bool = False


def _observation(value: HostObservation, url: str) -> dict:
    _require(
        type(value) is HostObservation
        and value.url == url
        and value.redirected is False
        and type(value.status) is int
        and value.status == 200,
        "observation is missing, redirected or from another endpoint",
    )
    return _json_body(value.body, MAX_OBSERVATION_BYTES)


def validate_repository(review: ReviewedGitHubCreate, observation: HostObservation) -> None:
    value = _observation(observation, review.repository_url)
    _require(
        type(value.get("id")) is int
        and value["id"] == review.repo_id
        and value.get("node_id") == review.repo_node_id,
        "repository identity changed",
    )
    _require(
        type(value.get("full_name")) is str
        and value["full_name"].isascii()
        and value["full_name"].lower() == f"{review.owner}/{review.repo}",
        "repository renamed or transferred",
    )
    _require(
        type(value.get("url")) is str
        and value["url"].isascii()
        and value["url"].lower() == review.repository_url,
        "repository API identity differs",
    )


def validate_preflight(
    request: GitHubCreateRequest,
    repository: HostObservation,
    branch: HostObservation,
    absent_contents: HostObservation,
    *,
    exclusive_writer: bool,
) -> None:
    """No CAS guarantee: caller must maintain exclusive writer through dispatch."""
    _require(exclusive_writer is True, "exclusive-writer deployment is required")
    r = request.review
    validate_repository(r, repository)
    value = _observation(branch, r.branch_ref_url)
    obj = value.get("object")
    _require(
        value.get("ref") == "refs/heads/" + r.branch
        and type(obj) is dict
        and obj.get("type") == "commit"
        and obj.get("sha") == r.expected_parent_sha,
        "branch does not match reviewed parent",
    )
    _require(
        type(absent_contents) is HostObservation
        and absent_contents.url == r.contents_at(r.expected_parent_sha)
        and absent_contents.redirected is False
        and type(absent_contents.status) is int
        and absent_contents.status == 404
        and type(absent_contents.body) is bytes
        and len(absent_contents.body) <= MAX_OBSERVATION_BYTES,
        "file absence at reviewed parent is not established",
    )


def validate_commit_observation(
    request: GitHubCreateRequest,
    observation: HostObservation,
    *,
    received201_commit_sha: str | None = None,
) -> str:
    """Return a safe immutable ref to fetch; observations remain untrusted data."""
    r = request.review
    value = _observation(observation, r.branch_commit_url)
    sha = value.get("sha")
    _require(_sha(sha, _SHA1), "invalid observed commit")
    if received201_commit_sha is not None:
        _require(
            _sha(received201_commit_sha, _SHA1) and sha == received201_commit_sha,
            "readback differs from acknowledged commit",
        )
    _require(
        type(value.get("url")) is str
        and value["url"].isascii()
        and value["url"].lower() == r.repository_url + "/commits/" + sha,
        "commit belongs to another endpoint",
    )
    commit, parents, files = value.get("commit"), value.get("parents"), value.get("files")
    _require(type(commit) is dict and commit.get("message") == r.message, "commit message differs")
    _require(
        type(parents) is list
        and len(parents) == 1
        and type(parents[0]) is dict
        and parents[0].get("sha") == r.expected_parent_sha,
        "commit is not anchored to reviewed parent",
    )
    _require(
        type(files) is list and len(files) == 1 and type(files[0]) is dict,
        "commit is not a single-file creation",
    )
    change = files[0]
    _require(
        change.get("filename") == r.path
        and change.get("status") == "added"
        and change.get("sha") == request.git_blob_sha1
        and "previous_filename" not in change,
        "commit does not add exact reviewed file",
    )
    return sha


@dataclass(frozen=True)
class ProviderConfirmation:
    outcome: str
    reason: str
    observation_hash: str
    commit_sha: str | None = None
    observation_kind: str = "anchored_provider_state"
    causal_attribution: str = "not_proven"


def confirm_create(
    request: GitHubCreateRequest,
    repository: HostObservation,
    commit: HostObservation,
    contents: HostObservation,
    *,
    exclusive_writer: bool,
    received201_commit_sha: str | None = None,
) -> ProviderConfirmation:
    """Return COMMITTED only for exact anchored state; never retry or refund."""
    summaries = []
    for observation in (repository, commit, contents):
        if (
            type(observation) is HostObservation
            and type(observation.body) is bytes
            and len(observation.body) <= MAX_OBSERVATION_BYTES
        ):
            summaries.append(hashlib.sha256(observation.body).hexdigest())
        else:
            summaries.append("invalid-or-oversized-observation")
    # Hashes only: no credential bytes, raw content, user names or emails leave
    # this validator in evidence. The caller binds this to effect/reservation/
    # attempt and signs reconciliation using its separate trusted authority.
    evidence = {
        "profile": PROFILE,
        "projection": request.review.projection,
        "reviewed_parent": request.review.expected_parent_sha,
        "body_hashes": summaries,
    }
    outcome, reason, sha = "AMBIGUOUS", "readback_not_confirmed", None
    try:
        _require(exclusive_writer is True, "exclusive-writer deployment is required")
        validate_repository(request.review, repository)
        sha = validate_commit_observation(
            request, commit, received201_commit_sha=received201_commit_sha
        )
        value = _observation(contents, request.review.contents_at(sha))
        _require(
            value.get("type") == "file"
            and "submodule_git_url" not in value
            and "target" not in value
            and value.get("path") == request.review.path
            and value.get("name") == request.review.path.rsplit("/", 1)[-1]
            and value.get("encoding") == "base64",
            "readback is not exact file data",
        )
        actual = _decode_content(value.get("content"), response=True)
        _require(
            type(value.get("size")) is int and value["size"] == request.content_size == len(actual),
            "readback size differs",
        )
        _require(
            value.get("sha") == request.git_blob_sha1 == _blob_sha(actual)
            and hashlib.sha256(actual).hexdigest() == request.review.content_sha256,
            "readback bytes or blob identity differ",
        )
        outcome, reason = (
            "COMMITTED",
            "exact_provider_state_observed_under_exclusive_writer_assumption",
        )
    except (GitHubConsequenceError, TypeError, AttributeError):
        sha = None
    evidence.update(
        outcome=outcome,
        commit_sha=sha,
        exclusive_writer=exclusive_writer is True,
        acknowledged_commit=received201_commit_sha if _sha(received201_commit_sha, _SHA1) else None,
    )
    return ProviderConfirmation(
        outcome, reason, hashlib.sha256(canonicalize_bytes(evidence)).hexdigest(), sha
    )
