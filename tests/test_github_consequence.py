"""Synthetic GitHub response validation; never live-provider evidence."""

import base64
import copy
import hashlib
import json
from dataclasses import replace

import pytest

from actenon_airlock.github_consequence import (
    MAX_OBSERVATION_BYTES,
    GitHubConsequenceError,
    HostObservation,
    ReviewedGitHubCreate,
    confirm_create,
    project_create,
    validate_preflight,
)

CONTENT = b"diff --git a/example.py b/example.py\n+fixed\n"
PARENT = "a" * 40
COMMIT = "b" * 40


def review(**updates):
    return ReviewedGitHubCreate(
        **dict(
            repo_id=123,
            repo_node_id="R_abc",
            owner="acme",
            repo="demo",
            branch="review",
            path="patches/fix.patch",
            message="publish reviewed patch",
            content_sha256=hashlib.sha256(CONTENT).hexdigest(),
            expected_parent_sha=PARENT,
            **updates,
        )
    )


def body(**updates):
    result = {
        "message": "publish reviewed patch",
        "content": base64.b64encode(CONTENT).decode(),
        "branch": "review",
    }
    result.update(updates)
    return json.dumps(result).encode()


def request():
    r = review()
    return project_create("PUT", r.contents_url, body(), r)


def obs(url, value, status=200):
    return HostObservation(url, status, json.dumps(value).encode())


def observations(req):
    r = req.review
    repository = obs(
        r.repository_url,
        {"id": 123, "node_id": "R_abc", "full_name": "acme/demo", "url": r.repository_url},
    )
    commit = obs(
        r.branch_commit_url,
        {
            "sha": COMMIT,
            "url": r.repository_url + "/commits/" + COMMIT,
            "commit": {"message": r.message},
            "parents": [{"sha": PARENT}],
            "files": [{"filename": r.path, "status": "added", "sha": req.git_blob_sha1}],
        },
    )
    contents = obs(
        r.contents_at(COMMIT),
        {
            "type": "file",
            "path": r.path,
            "name": "fix.patch",
            "encoding": "base64",
            "content": base64.b64encode(CONTENT).decode() + "\n",
            "size": len(CONTENT),
            "sha": req.git_blob_sha1,
        },
    )
    return repository, commit, contents


def test_exact_projection_ignores_serialization_and_does_not_expose_reset_metadata():
    r = review()
    first = project_create("PUT", r.contents_url, body(), r)
    reordered = json.dumps(json.loads(body()), sort_keys=True, indent=2).encode()
    second = project_create("PUT", r.contents_url, reordered, r)
    assert first.body == second.body
    assert first.effect_descriptor("reviewed-owner") == second.effect_descriptor("reviewed-owner")
    assert first.action == "github.contents.write"
    assert first.resource == "github.com/acme/demo"
    assert (
        first.git_blob_sha1
        == hashlib.sha1(
            b"blob " + str(len(CONTENT)).encode() + b"\0" + CONTENT, usedforsecurity=False
        ).hexdigest()
    )
    assert first.effect_descriptor("reviewed-owner") == project_create(
        "PUT", r.contents_url, body(), replace(r, expected_parent_sha="c" * 40)
    ).effect_descriptor("reviewed-owner")


@pytest.mark.parametrize(
    "extra",
    [
        {"sha": "a" * 40},
        {"author": {}},
        {"committer": {}},
        {"trace_id": "reset"},
        {"grant_id": "reset"},
        {"session_id": "reset"},
        {"Message": "alias"},
        {"content": "!!!!"},
        {"content": "Zg==\n"},
        {"branch": "other"},
        {"message": "unreviewed"},
        {"content": base64.b64encode(b"other").decode()},
        {"branch": 1},
        {"message": 1.0},
    ],
)
def test_closed_body_refuses_expansion(extra):
    with pytest.raises(GitHubConsequenceError):
        project_create("PUT", review().contents_url, body(**extra), review())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"message":"a","message":"b"}',
        b"[]",
        b"null",
        b"\xff",
        body().decode().encode("utf-16"),
        b"\xef\xbb\xbf" + body(),
    ],
)
def test_ambiguous_raw_body_refused(raw):
    with pytest.raises(GitHubConsequenceError):
        project_create("PUT", review().contents_url, raw, review())


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/repos/acme/demo/contents/patches/fix.patch",
        "https://api.github.com:443/repos/acme/demo/contents/patches/fix.patch",
        "https://api.github.com/repos/acme/demo/contents/patches/%66ix.patch",
        "https://api.github.com/repos/acme/demo/contents/patches/fix.patch?ref=main",
        "https://api.github.com/repos/acme/other/contents/patches/fix.patch",
        "https://api.github.com/repos/acme/demo/issues",
        "https://evil.example/repos/acme/demo/contents/patches/fix.patch",
    ],
)
def test_exact_url_required(url):
    with pytest.raises(GitHubConsequenceError):
        project_create("PUT", url, body(), review())


@pytest.mark.parametrize(
    "path",
    ["../secret", "a//b", "a/./b", ".github/workflows/a.yml", "a/.git/config", "a%2fb", "a\\b"],
)
def test_unsupported_path_refused(path):
    with pytest.raises(GitHubConsequenceError):
        replace(review(), path=path)


def test_confirmed_provider_state_requires_exact_anchored_observations():
    req = request()
    result = confirm_create(
        req, *observations(req), exclusive_writer=True, received201_commit_sha=COMMIT
    )
    assert result.outcome == "COMMITTED"
    assert result.commit_sha == COMMIT
    assert result.observation_kind == "anchored_provider_state"
    assert result.causal_attribution == "not_proven"
    assert len(result.observation_hash) == 64


@pytest.mark.parametrize("exclusive", [False, 1, None])
def test_no_supported_writer_assumption_means_ambiguous(exclusive):
    req = request()
    assert (
        confirm_create(req, *observations(req), exclusive_writer=exclusive).outcome == "AMBIGUOUS"
    )


@pytest.mark.parametrize(
    "which,key,value",
    [
        (0, "id", 456),
        (0, "id", True),
        (0, "node_id", "R_changed"),
        (0, "full_name", "other/demo"),
        (1, "parents", [{"sha": "c" * 40}]),
        (1, "parents", []),
        (1, "parents", [{"sha": PARENT}, {"sha": "c" * 40}]),
        (1, "files", []),
        (1, "sha", "not-a-sha"),
        (1, "commit", {"message": "other"}),
        (2, "sha", "c" * 40),
        (2, "size", True),
        (2, "size", 1),
        (2, "path", "other.patch"),
        (2, "type", "symlink"),
        (2, "encoding", "none"),
        (2, "content", base64.b64encode(b"other").decode()),
    ],
)
def test_conflicting_provider_state_never_confirms(which, key, value):
    req = request()
    observed = list(observations(req))
    data = json.loads(observed[which].body)
    data[key] = value
    observed[which] = replace(observed[which], body=json.dumps(data).encode())
    assert confirm_create(req, *observed, exclusive_writer=True).outcome == "AMBIGUOUS"


def test_existing_modified_file_or_extra_file_cannot_confirm_creation():
    req = request()
    for change in ("modified", "renamed", "removed"):
        observed = list(observations(req))
        data = json.loads(observed[1].body)
        data["files"][0]["status"] = change
        observed[1] = replace(observed[1], body=json.dumps(data).encode())
        assert confirm_create(req, *observed, exclusive_writer=True).outcome == "AMBIGUOUS"
    observed = list(observations(req))
    data = json.loads(observed[1].body)
    data["files"].append(copy.deepcopy(data["files"][0]))
    observed[1] = replace(observed[1], body=json.dumps(data).encode())
    assert confirm_create(req, *observed, exclusive_writer=True).outcome == "AMBIGUOUS"


@pytest.mark.parametrize(
    "change",
    [
        {"status": 404},
        {"status": 201},
        {"redirected": True},
        {"url": "https://evil.example"},
        {"body": b"{}"},
        {"body": b"x" * (MAX_OBSERVATION_BYTES + 1)},
        {"body": b'{"id":123,"id":456}'},
    ],
)
def test_absent_malformed_redirected_or_oversized_observation_is_ambiguous(change):
    req = request()
    observed = list(observations(req))
    observed[0] = replace(observed[0], **change)
    assert confirm_create(req, *observed, exclusive_writer=True).outcome == "AMBIGUOUS"


def test_received_ack_cannot_be_replaced_with_another_matching_commit():
    req = request()
    assert (
        confirm_create(
            req, *observations(req), exclusive_writer=True, received201_commit_sha="c" * 40
        ).outcome
        == "AMBIGUOUS"
    )


def test_preflight_requires_reviewed_existing_branch_and_file_absence():
    req = request()
    repository, _, _ = observations(req)
    r = req.review
    branch = obs(
        r.branch_ref_url, {"ref": "refs/heads/review", "object": {"type": "commit", "sha": PARENT}}
    )
    absent = HostObservation(r.contents_at(PARENT), 404, b'{"message":"Not Found"}')
    validate_preflight(req, repository, branch, absent, exclusive_writer=True)
    for changed in [replace(absent, status=200), replace(absent, redirected=True)]:
        with pytest.raises(GitHubConsequenceError):
            validate_preflight(req, repository, branch, changed, exclusive_writer=True)
    with pytest.raises(GitHubConsequenceError):
        validate_preflight(req, repository, branch, absent, exclusive_writer=False)


def test_finite_approved_identity_needs_no_agent_body_and_new_path_is_distinct():
    from actenon_protocol.effects import effect_identity

    req = request()
    assert effect_identity(req.review.effect_descriptor("owner")) == effect_identity(
        req.effect_descriptor("owner")
    )
    next_review = replace(req.review, path="patches/another.patch")
    next_request = project_create("PUT", next_review.contents_url, body(), next_review)
    assert effect_identity(next_request.effect_descriptor("owner")) != effect_identity(
        req.effect_descriptor("owner")
    )


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize(
    "changes",
    [{"status": 404}, {"status": True}, {"redirected": True}, {"body": b"\xff"}, {"body": b"[]"}],
)
def test_every_observation_is_required_and_strict(index, changes):
    req = request()
    observed = list(observations(req))
    observed[index] = replace(observed[index], **changes)
    assert confirm_create(req, *observed, exclusive_writer=True).outcome == "AMBIGUOUS"


@pytest.mark.parametrize("index", [0, 1, 2])
def test_unavailable_observation_is_ambiguous(index):
    req = request()
    observed = list(observations(req))
    observed[index] = None
    assert confirm_create(req, *observed, exclusive_writer=True).outcome == "AMBIGUOUS"


def test_content_observation_must_be_at_the_confirmed_immutable_commit():
    req = request()
    observed = list(observations(req))
    observed[2] = replace(observed[2], url=req.review.contents_at(PARENT))
    assert confirm_create(req, *observed, exclusive_writer=True).outcome == "AMBIGUOUS"


@pytest.mark.parametrize(
    "changes",
    [
        {"repo_id": True},
        {"repo_id": 0},
        {"repo_node_id": "R_\0"},
        {"expected_parent_sha": "main"},
        {"expected_parent_sha": "A" * 40},
        {"branch": "a..b"},
        {"branch": ".hidden"},
        {"branch": "a.lock"},
        {"branch": "a//b"},
        {"branch": "a%2Fb"},
        {"branch": "a" * 40},
        {"content_sha256": "bad"},
        {"message": " leading"},
    ],
)
def test_reviewed_profile_itself_is_closed_to_ambiguous_fields(changes):
    with pytest.raises(GitHubConsequenceError):
        replace(review(), **changes)


def test_content_and_observations_cannot_escape_bounds():
    r = review()
    from actenon_airlock.github_consequence import MAX_CONTENT_BYTES, MAX_REQUEST_BYTES

    too_big = b"a" * (MAX_CONTENT_BYTES + 1)
    with pytest.raises(GitHubConsequenceError):
        project_create(
            "PUT",
            r.contents_url,
            body(content=base64.b64encode(too_big).decode()),
            replace(r, content_sha256=hashlib.sha256(too_big).hexdigest()),
        )
    with pytest.raises(GitHubConsequenceError):
        project_create("PUT", r.contents_url, b" " * (MAX_REQUEST_BYTES + 1), r)
