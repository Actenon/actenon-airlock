"""Part two of `airlock demo`: one exact, approved change, checked and verified.

It takes the candidate the sealed run in part one really produced, and takes it through
the same product path a real publish uses:

  check it with your tests in a sealed container -> discover and review the one power it
  needs -> sign only that -> refuse what was not approved -> send it once -> read the
  result back, and check that independently -> report what is known.

"GitHub" here is Airlock's local synthetic provider: a file that records every request.
Nothing leaves this machine, no account is used, and the output says so. Every line of
the receipt comes from the signed journal, the provider's own record or the candidate
bytes, never from this script's expectations.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import shutil
from pathlib import Path

from .agents import DECLARATION, HEADER
from .common import AirlockError
from .credential_preflight import supervisor_scope
from .github_consequence import ReviewedGitHubCreate
from .github_runtime import PROFILE_SCHEMA
from .state import State

OWNER, REPO, BRANCH = "airlock-demo", "calculator", "main"
PATH_IN_REPO = "fixes/calculator.patch"
MESSAGE = "Fix add() (approved through Airlock)"
TESTS = (
    "from calculator import add\n\n\n"
    "def test_adds():\n    assert add(2, 3) == 5\n\n\n"
    "def test_adds_negatives():\n    assert add(-2, -3) == -5\n"
)


def _quiet(call, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return call(*args, **kwargs)


def _provider_puts(provider: Path) -> int:
    return sum(r["method"] == "PUT" for r in json.loads(provider.read_text())["requests"])


def independent_check(provider: Path, review: ReviewedGitHubCreate) -> dict:
    """Read the provider's own state directly, not through Airlock: bytes, parent, path."""
    world = json.loads(provider.read_text())
    commit = world["commits"][world["head"]]
    entry = world["files"].get(review.path, {})
    content = base64.b64decode(entry.get("content", "")) if entry else b""
    checks = {
        "file_bytes_match_approved_candidate": hashlib.sha256(content).hexdigest()
        == review.content_sha256,
        "commit_parent_is_reviewed_parent": commit.get("parent") == review.expected_parent_sha,
        "commit_touches_only_the_reviewed_path": [f["filename"] for f in commit.get("files", [])]
        == [review.path],
    }
    return {"source": "synthetic provider state file, read directly (not via Airlock)",
            "commit_sha": world["head"], "checks": checks,
            "confirmed": all(checks.values())}  # fmt: skip


def run(state: State, run_dir: Path, workspace_root: Path, cli_main, image: str) -> dict:
    """The second act. Returns facts for the receipt; raises if a step cannot be shown."""
    from .consequence_report import build_report
    from .synthetic_github import TOKEN, create_provider, synthetic_client
    from .workflow import (
        TESTS_PASSED,
        capture_candidate,
        publish_candidate,
        status,
        verify_candidate,
    )

    root = state.root
    out = workspace_root / "act-two"
    out.mkdir()
    facts: dict = {}

    # 1. The candidate the sealed run produced, and your tests, in a sealed container.
    manifest = capture_candidate(state, run_dir)
    candidate = manifest["candidate_sha256"]
    tests = out / "your-tests"
    tests.mkdir()
    (tests / "test_calculator.py").write_text(TESTS)
    check = _quiet(verify_candidate, state, candidate, tests, image=image, profile="python")
    facts["candidate"] = manifest
    facts["check"] = check
    if check["verdict"] != TESTS_PASSED:
        raise AirlockError("the candidate did not pass its checks: " + check["detail"])

    # 2. Discover and review the one power this change needs; sign only that.
    provider = out / "github.json"
    create_provider(provider, owner=OWNER, repo=REPO, branch=BRANCH)
    world = json.loads(provider.read_text())
    review = ReviewedGitHubCreate(
        repo_id=world["repository"]["id"], repo_node_id=world["repository"]["node_id"],
        owner=OWNER, repo=REPO, branch=BRANCH, expected_parent_sha=world["head"],
        path=PATH_IN_REPO, message=MESSAGE, content_sha256=candidate,
    )  # fmt: skip
    profile = out / "reviewed-create.json"
    profile.write_text(json.dumps({"schema": PROFILE_SCHEMA, "exclusive_writer": True,
                                   "credential_name": "GITHUB_TOKEN",
                                   "review": review.__dict__}, indent=2))  # fmt: skip
    # The declaration Scan reads, as `airlock review-candidate` writes it. Never executed.
    (root / DECLARATION).write_text(
        HEADER + "\n\nimport requests\n\n" + f'requests.put("{review.contents_url}")\n'
    )
    key = out / "operator.key"
    review_text = io.StringIO()
    with contextlib.redirect_stdout(review_text):
        signed = cli_main(["init", "--path", str(root), "--approve", "--only-reviewed",
                           "--github-create", str(profile), "--reconciler-key", str(key),
                           "--credential", "GITHUB_TOKEN=https://api.github.com"])  # fmt: skip
    if signed:
        raise AirlockError("the reviewed approval could not be signed")
    facts["review"] = review_text.getvalue()
    facts["signed_powers"] = [f"{p['action']} {p['resource']}" for p in state.approved()["powers"]]
    withheld = state.approved().get("not_granted", [])
    facts["not_granted"] = len(withheld)
    from .authority_review import describe

    facts["not_granted_examples"] = [describe(p) for p in withheld[:2]]

    def client():
        return synthetic_client(provider)

    def attempt(sha):
        with supervisor_scope("GITHUB_TOKEN", TOKEN):
            try:
                return _quiet(publish_candidate, state, sha, client=client())
            except AirlockError as exc:
                return {"status": "REFUSED", "reason": str(exc)}

    # 3. What was not approved is refused before anything is sent.
    variant = run_dir.parent / (run_dir.name + "-edited")
    shutil.copytree(run_dir, variant, symlinks=True)
    edited = variant / "workspace" / "calculator.py"
    edited.write_text(edited.read_text() + "# edited after review\n")
    altered = capture_candidate(state, variant)["candidate_sha256"]
    altered_check = _quiet(verify_candidate, state, altered, tests, image=image, profile="python")
    refusals = [("an edited copy of the approved patch (it also passes)",
                 attempt(altered), altered_check["verdict"])]  # fmt: skip
    from .manifest import discover
    from .protected import ProtectedBroker

    with supervisor_scope("GITHUB_TOKEN", TOKEN):
        broker = ProtectedBroker(state, discover(root), state.approved()["credential_bindings"])
        broker.http.close()
        broker.http = client()
        try:
            other = review.repository_url + "/contents/fixes/something-else.patch"
            body = json.dumps({"branch": BRANCH, "message": MESSAGE,
                               "content": base64.b64encode(b"x").decode()}).encode()  # fmt: skip
            reply = _quiet(broker.handle, {"kind": "protected-http", "method": "PUT",
                                           "url": other, "headers": {},
                                           "body": base64.b64encode(body).decode()})  # fmt: skip
        finally:
            broker.close()
    refusals.append(("a write to another file in the same repository",
                     {"status": "REFUSED" if not reply.get("ok") else "SENT",
                      "reason": reply.get("reason")}, None))  # fmt: skip
    facts["refusals"] = refusals
    facts["puts_before_approved"] = _provider_puts(provider)

    # 4. The approved change, once. Its reply is not taken as proof.
    sent = attempt(candidate)
    facts["sent"] = sent
    facts["unresolved_after_send"] = list(status(state)["unresolved_effects"])
    replay = attempt(candidate)
    facts["replay"] = replay
    facts["puts_after"] = _provider_puts(provider)

    # 5. Settle it only by reading GitHub back, then check that independently.
    effect = sent.get("effect_id")
    with supervisor_scope("GITHUB_TOKEN", TOKEN):
        settled = _quiet(cli_main, ["reconcile", "--path", str(root), effect, "--github-readback",
                                    "--operator-key", str(key), "--synthetic-provider",
                                    str(provider)])  # fmt: skip
    independent = independent_check(provider, review)
    report = build_report(state, effect, independent=independent, candidate=candidate)
    final = status(state)
    facts.update(effect=effect, settled_exit=settled, independent=independent,
                 report_status=report.get("status"), final=final, review_obj=review)  # fmt: skip
    return facts


def _yes(flag: bool, good: str, bad: str) -> str:
    return good if flag else bad


def render(facts: dict) -> tuple[list[str], list[str]]:
    """The second act's lines, and any reason the run cannot be claimed."""
    review: ReviewedGitHubCreate = facts["review_obj"]
    check, manifest = facts["check"], facts["candidate"]
    changed = ", ".join(c["path"] for c in manifest["changes"])
    refused_ok = all(r["status"] == "REFUSED" for _, r, _ in facts["refusals"])
    replay_ok = facts["replay"]["status"] == "REFUSED"
    held = (
        facts["sent"]["status"] in {"DISPATCHED_UNCONFIRMED", "AMBIGUOUS"}
        and facts["effect"] in facts["unresolved_after_send"]
    )
    settled = (
        facts["settled_exit"] == 0 and facts["effect"] not in facts["final"]["unresolved_effects"]
    )
    independent = facts["independent"]["confirmed"]
    counts = check["checks"][0].get("counts") or {}
    problems = []
    if not refused_ok:
        problems.append("an unapproved write was not refused")
    if facts["puts_before_approved"] != 0:
        problems.append("a request reached GitHub before the approved write")
    if facts["puts_after"] != 1:
        problems.append(f"GitHub received {facts['puts_after']} writes, not exactly one")
    if not (held and replay_ok and settled and independent):
        problems.append("the approved write was not held, settled and independently confirmed")
    if facts["report_status"] != "CONFIRMED":
        problems.append(f"the consequence report says {facts['report_status']}")

    w = 16
    lines = [
        "Part 2: one approved change, checked, sent once and verified",
        "",
        f"The sealed run left one candidate: {changed} (patch {manifest['candidate_sha256'][:12]}).",
        "",
        f"{'1 Check':<{w}}{check['outcome']}  {counts.get('passed', 0)} of your tests passed, "
        "in a sealed container with no network",
        f"{'2 Review':<{w}}Airlock found what this project's code could do, and proposes one grant:",
        f"{'':<{w}}  create {review.path} in {review.owner}/{review.repo}, branch {review.branch},",
        f"{'':<{w}}  on commit {review.expected_parent_sha[:12]}, with exactly these bytes "
        f"(sha256 {review.content_sha256[:12]})",
        f"{'':<{w}}Found in the code but not granted: {facts['not_granted']}"
        + (f" ({'; '.join(facts['not_granted_examples'])})" if facts["not_granted"] else ""),
        f"{'':<{w}}Signed: {len(facts['signed_powers'])} grant. A real run asks you first; "
        "the demo approves for you.",
        f"{'3 Refuse':<{w}}"
        + "\n".join(
            (f"{'':<{w}}" if i else "")
            + f"{label:<56}"
            + _yes(result["status"] == "REFUSED", "refused, nothing sent", "NOT REFUSED")
            for i, (label, result, _) in enumerate(facts["refusals"])
        ),
        f"{'4 Act':<{w}}{'the approved file creation':<56}"
        + _yes(held, "sent once, held as unconfirmed", "not held"),
        f"{'':<{w}}{'the same request again':<56}"
        + _yes(replay_ok, "refused: it would duplicate", "NOT REFUSED"),
        f"{'5 Verify':<{w}}{'Airlock read GitHub back':<56}"
        + _yes(settled, "CONFIRMED", "not settled"),
        f"{'':<{w}}{'an independent check of GitHub’s own record':<56}"
        + _yes(independent, "bytes, parent and path match", "MISMATCH"),
        "",
        "RECEIPT",
        f"  {'Changed':<11}{len(manifest['changes'])} file ({changed})",
        f"  {'Checked':<11}{check['outcome']}: {check['detail']}",
        f"  {'Approved':<11}1 exact file creation, nothing else",
        f"  {'Refused':<11}{len(facts['refusals']) + 1} attempts, none reached GitHub",
        f"  {'Happened':<11}{facts['puts_after']} file created on GitHub, "
        + _yes(independent and settled, "confirmed independently", "NOT confirmed"),
        f"  {'Uncertain':<11}"
        + _yes(not facts["final"]["unresolved_effects"], "nothing", "unresolved effects remain"),
        f"  {'Evidence':<11}{facts['final']['receipts']} signed receipts, integrity "
        + _yes(facts["final"]["integrity_ok"], "OK", "FAILED"),
        f"  {'Outcome':<11}{facts['report_status']} (from airlock explain)",
        "",
        "GitHub here is Airlock's local stand-in, which records every request. No account was",
        "used and nothing left this machine. The agent, the boundary, the approval, the refusals",
        "and both readbacks are the real product.",
    ]
    return lines, problems
