"""Host orchestration for one reviewed GitHub Contents create-only profile.

Permit grants and Kernel effect ownership remain the authorization system.
This adapter supplies provider semantics and a bounded, credential-owning
transport. It never infers committed provider state from HTTP success.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import asdict

import httpx
from actenon_protocol.canonicalisation import parse_strict

from .broker import HttpDispatch
from .common import AirlockError, digest, origin, power
from .github_consequence import (
    MAX_OBSERVATION_BYTES,
    HostObservation,
    ReviewedGitHubCreate,
    project_create,
    validate_preflight,
    validate_repository,
)
from .manifest import capability

PROFILE_SCHEMA = "actenon-airlock/github-create/v1"


def validate_profiles(values):
    if type(values) is not list or len(values) > 16:
        raise AirlockError("At most 16 separately reviewed GitHub creations are supported")
    profiles, targets = [], set()
    for value in values:
        if (
            type(value) is not dict
            or set(value) != {"schema", "review", "exclusive_writer", "credential_name"}
            or value["schema"] != PROFILE_SCHEMA
            or value["exclusive_writer"] is not True
            or value["credential_name"] not in {"GITHUB_TOKEN", "GH_TOKEN"}
            or type(value["review"]) is not dict
        ):
            raise AirlockError(
                "GitHub creation requires an exact reviewed exclusive-writer profile"
            )
        try:
            review = ReviewedGitHubCreate(**value["review"])
        except (TypeError, ValueError) as exc:
            raise AirlockError("Invalid reviewed GitHub creation") from exc
        target = (review.repo_id, review.branch, review.path)
        if target in targets:
            raise AirlockError("A GitHub file may have only one reviewed creation per approval")
        targets.add(target)
        profiles.append({**value, "review": asdict(review)})
    return profiles


def review_for(profile):
    return ReviewedGitHubCreate(**profile["review"])


def scan_power(review):
    # ReviewedGitHubCreate has already required Scan's resolved named power.
    return power("github.contents.write", review.resource, origin(review.contents_url))


def effect_descriptor(review, namespace):
    value = review.effect_descriptor(namespace)
    # The existing Airlock capability binds Scan action/resource/transport;
    # Permit expresses targets as 'tool'. Kernel checks both fields exactly.
    value["action_type"] = capability(scan_power(review))
    value["target"]["type"] = "tool"
    return value


def read_observation(client, url, headers):
    """Fetch only a host-derived GitHub URL; never follow provider redirects."""
    with client.stream("GET", url, headers=headers, timeout=30, follow_redirects=False) as response:
        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > MAX_OBSERVATION_BYTES:
                raise AirlockError("GitHub observation exceeds the supported bound")
            body.extend(chunk)
        return HostObservation(
            str(response.url), response.status_code, bytes(body), bool(response.history)
        )


class GitHubCreateDispatch(HttpDispatch):
    def __init__(self, broker, effect, message, profile):
        self.profile = profile
        self.request = project_create(
            effect.params["method"],
            effect.target,
            base64.b64decode(message.get("body", ""), validate=True),
            review_for(profile),
        )
        marker = broker.markers.get(profile["credential_name"])
        if marker is None or broker.credentials[marker][1] != "https://api.github.com":
            raise AirlockError("The reviewed repository-scoped GitHub credential is unavailable")
        # Canonicalize before authority evaluation. Trace and agent-selected
        # headers never change provider semantics or reset effect ownership.
        prepared = {
            **message,
            "body": base64.b64encode(self.request.body).decode(),
            "headers": {
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Authorization": "Bearer " + marker,
            },
        }
        super().__init__(broker, effect, prepared)
        self.params["github_body"] = base64.b64encode(self.body).decode()
        self.consequential = True
        self.preflight = []
        self.acknowledged_commit = None

    def authority_fields(self):
        return {"github_profile": self.profile}

    def receipt_fields(self):
        return {
            "observation_stage": "creation" if self.attempted else "preflight",
            "github_preflight": self.preflight,
            "github_commit_sha": self.acknowledged_commit,
        }

    def run(self):
        # Kernel has already claimed this exact finite effect before this
        # callback can materialize credentials or perform host observations.
        r = self.request.review
        headers, self.credential_released = self.broker._headers(
            self.headers, self.url, materialize=True
        )

        def observe(url):
            value = read_observation(self.broker.http, url, headers)
            self.preflight.append(
                {
                    "url": value.url,
                    "status": value.status,
                    "body_sha256": hashlib.sha256(value.body).hexdigest(),
                }
            )
            return value

        try:
            repository = observe(r.repository_url)
            validate_repository(r, repository)
            branch = observe(r.branch_ref_url)
            absent = observe(r.contents_at(r.expected_parent_sha))
            validate_preflight(
                self.request,
                repository,
                branch,
                absent,
                exclusive_writer=self.profile["exclusive_writer"],
            )
        except (AirlockError, ValueError, httpx.HTTPError):
            # The fixed host callback has not sent the creation request. It
            # can report that fact without interpreting a mutation timeout.
            return {
                "effect_evidence": {
                    **self.effect_reference,
                    "outcome": "NOT_EXECUTED",
                    "execution_occurred": False,
                    "evidence_hash": digest({"stage": "preflight", "observations": self.preflight}),
                }
            }
        # attempted means the protected creation request, not verifier GETs.
        result = super().run()
        if self.response.get("status") == 201:
            try:
                value = parse_strict(
                    base64.b64decode(self.response["body"], validate=True).decode("utf-8")
                )
                sha = value["commit"]["sha"]
                if type(sha) is str and re.fullmatch(r"[0-9a-f]{40}", sha):
                    self.acknowledged_commit = sha
            except (ValueError, KeyError, TypeError):
                pass  # A missing/ambiguous acknowledgement never establishes commit.
        return result


def project_intent(intent, profiles, namespace):
    """Independently derive the provider identity from the signed exact request."""
    for profile in profiles:
        review = review_for(profile)
        if intent.target.resource_id != review.contents_url:
            continue
        params = intent.action.parameters
        try:
            request = project_create(
                params["method"],
                intent.target.resource_id,
                base64.b64decode(params["github_body"], validate=True),
                review,
            )
        except ValueError:
            continue
        if request.body_sha256 != params["body_sha256"]:
            raise AirlockError("GitHub proof projection differs from its exact dispatch body")
        expected = effect_descriptor(review, namespace)
        if intent.action.capability != expected["action_type"]:
            raise AirlockError("GitHub proof does not name the reviewed Scan capability")
        return expected
    raise AirlockError("No reviewed GitHub consequence matches this request")


def read_profile_file(path):
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise AirlockError("GitHub review profile exceeds 64 KiB")
    value = parse_strict(raw.decode("utf-8", errors="strict"))
    return validate_profiles([value])[0]
