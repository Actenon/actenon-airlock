"""Host-only, bounded readback for an already claimed GitHub creation.

This helper never PUTs, retries, refunds, or settles a ledger entry. It signs a
COMMITTED observation only under the original reviewed exclusive-writer
assumption; which process caused the observed commit remains not proven.

Evidence stays owner-only below .airlock/local. It contains exact request bytes
and bounded provider response bodies (which may include private code or GitHub
user metadata), plus their hashes; it is not a public export. Request/response
headers and exception messages are never recorded. A response echoing the active
credential literally or in its base64 content is retained as a hash only. Request
bodies containing that credential, including in decoded content, are hash-only. No automatic upload or
redaction of unrelated private code is performed.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from contextlib import nullcontext
from dataclasses import asdict
from uuid import uuid4

import httpx
from actenon.models import ActionIntent
from actenon.proof import build_action_hash_input
from actenon.proof.canonical import sha256_hex
from actenon_protocol.canonicalisation import parse_strict
from actenon_protocol.effects import effect_identity

from .common import AirlockError, canonical, digest
from .github_consequence import (
    MAX_REQUEST_BYTES,
    confirm_create,
    project_create,
    validate_commit_observation,
    validate_repository,
)
from .github_runtime import project_intent, read_observation, review_for, validate_profiles
from .reconciliation import operator_identity, prepare_reconciliation, sign_reconciliation

OBSERVATION_SCHEMA = "actenon-airlock/github-observation/v1"


def _original_request(state, snapshot):
    """Require the signed original review, not a possibly changed current one."""
    journal = state.verify_receipts()
    if not journal["ok"]:
        raise AirlockError("Receipt journal is invalid; GitHub observation is unavailable")
    candidates = [
        item["row"]
        for item in journal["rows"]
        if item["row"].get("stage") == "authorized"
        and item["row"].get("grant_id") == snapshot["grant_id"]
        and item["row"].get("proof", {}).get("extensions", {}).get("effect")
        == snapshot["reference"]
    ]
    if len(candidates) != 1:
        raise AirlockError("The exact signed original GitHub request is unavailable")
    row = candidates[0]
    try:
        profile = validate_profiles([row["github_profile"]])[0]
        intent = ActionIntent.from_dict(row["intent"])
        params = intent.action.parameters
        encoded = params["github_body"]
        if type(encoded) is not str or len(encoded) > 4 * ((MAX_REQUEST_BYTES + 2) // 3):
            raise ValueError("unsupported stored body")
        raw = base64.b64decode(encoded, validate=True)
        request = project_create(
            params["method"], intent.target.resource_id, raw, review_for(profile)
        )
        descriptor = project_intent(
            intent, [profile], "airlock-local:" + snapshot["project_key_hash"]
        )
        if (
            request.body != raw
            or request.body_sha256 != params["body_sha256"]
            or effect_identity(descriptor) != snapshot["reference"]["effect_id"]
            or digest(descriptor) != snapshot["descriptor_hash"]
            or sha256_hex(build_action_hash_input(intent)) != snapshot["action_hash"]
            or row["proof"]["action_hash"]["value"] != snapshot["action_hash"]
            or row["proof_id"] != snapshot["proof_id"]
            or intent.target.resource_id != snapshot["target"]
        ):
            raise ValueError("request differs from ledger binding")
        acknowledgements = {
            item["row"]["github_commit_sha"]
            for item in journal["rows"]
            if item["row"].get("parent_receipt_id") == row["id"]
            and item["row"].get("grant_id") == snapshot["grant_id"]
            and item["row"].get("github_commit_sha") is not None
        }
        if len(acknowledgements) > 1:
            raise ValueError("conflicting signed acknowledgements")
        acknowledged = next(iter(acknowledgements), None)
    except (ValueError, KeyError, TypeError, AirlockError) as exc:
        raise AirlockError("Original GitHub review/request does not match the held effect") from exc
    return request, profile, row["id"], acknowledged


def _body_record(body, secret, *, content=False):
    record = {"body_sha256": hashlib.sha256(body).hexdigest(), "body_length": len(body)}
    sensitive = secret in body
    try:
        value = parse_strict(body.decode("utf-8"))
        encoded = value.get("content") if type(value) is dict else None
        if type(encoded) is str:
            sensitive |= secret in base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        if content:
            raise AirlockError("Original creation body is invalid") from None
    if sensitive:
        record["body_redacted"] = "active_credential_detected"
    else:
        record["body_base64"] = base64.b64encode(body).decode("ascii")
    return record


def _save_observation(state, artifact):
    # The runtime excludes .airlock from the contained worker. These modes also
    # protect host evidence from other local users; this is not an OS jail.
    if state.path.is_symlink() or state.local.is_symlink():
        raise AirlockError("Observation storage may not be a symlink")
    info = state.local.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise AirlockError("Observation storage must be an owner-only directory")
    directory = os.open(state.local, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = "github-observation-" + uuid4().hex + ".json"
    body = canonical(artifact) + b"\n"
    try:
        fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)
    return state.local / name, hashlib.sha256(body).hexdigest()


def observe_github(state, effect_id, private, *, client=None):
    """Observe exact held state and return evidence, never change authority/state.

    ``client`` is a trusted host dependency-injection seam for fixture transport,
    never selected by agent input. The ordinary client verifies TLS, ignores
    ambient proxy configuration, and follows no redirects. A failed observation
    remains AMBIGUOUS; 404 does not establish non-execution.
    """
    approved = state.approved()
    key_id, public = operator_identity(private)
    if approved.get("reconciliation_keys", {}).get(key_id) != public:
        raise AirlockError("GitHub observer key is not authorized by the current approval")
    snapshot = prepare_reconciliation(state, effect_id)
    if snapshot["approval_digest"] != digest(approved):
        raise AirlockError("Approval changed; obtain a fresh GitHub observation")
    if snapshot["prior_state"] not in {"DISPATCHING", "AMBIGUOUS"}:
        raise AirlockError("GitHub observation requires an already claimed, unsettled effect")
    request, profile, receipt_id, acknowledged = _original_request(state, snapshot)
    # Only now may this host helper read the configured credential.
    credential = os.environ.get(profile["credential_name"])
    secret = credential.encode("utf-8") if credential else b"\0missing-credential\0"
    artifact = {
        "schema": OBSERVATION_SCHEMA,
        "request": snapshot,
        "request_hash": digest(snapshot),
        "authorized_receipt_id": receipt_id,
        "github_profile": profile,
        "creation": _body_record(request.body, secret, content=True),
        "acknowledged_commit": acknowledged,
        "observations": [],
        "outcome": "AMBIGUOUS",
        "reason": "credential_unavailable",
        "observation_kind": "anchored_provider_state",
        "causal_attribution": "not_proven",
    }
    if credential:
        headers = {
            "Authorization": "Bearer " + credential,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        manager = (
            nullcontext(client)
            if client is not None
            else httpx.Client(follow_redirects=False, trust_env=False)
        )

        def observe(transport, url):
            value = read_observation(transport, url, headers)
            artifact["observations"].append(
                {
                    "url": value.url,
                    "status": value.status,
                    "redirected": value.redirected,
                    **_body_record(value.body, secret),
                }
            )
            return value

        try:
            with manager as transport:
                repository = observe(transport, request.review.repository_url)
                validate_repository(request.review, repository)
                commit = observe(transport, request.review.branch_commit_url)
                sha = validate_commit_observation(
                    request, commit, received201_commit_sha=acknowledged
                )
                contents = observe(transport, request.review.contents_at(sha))
                confirmation = confirm_create(
                    request,
                    repository,
                    commit,
                    contents,
                    exclusive_writer=profile["exclusive_writer"],
                    received201_commit_sha=acknowledged,
                )
                artifact.update(asdict(confirmation))
        except (AirlockError, ValueError, httpx.HTTPError):
            # Never persist provider exception messages: they can include headers
            # or response bodies. Complete bounded observations remain preserved.
            artifact["reason"] = "readback_not_confirmed"
    path, evidence_hash = _save_observation(state, artifact)
    result = {
        "outcome": artifact["outcome"],
        "observation_path": str(path),
        "observation_hash": evidence_hash,
        "reason": artifact["reason"],
        "observation_kind": artifact["observation_kind"],
        "causal_attribution": artifact["causal_attribution"],
        "provider_dispatched": False,
    }
    if artifact["outcome"] == "COMMITTED":
        result["envelope"] = sign_reconciliation(
            snapshot, private, outcome="COMMITTED", evidence_hash=evidence_hash
        )
    return result
