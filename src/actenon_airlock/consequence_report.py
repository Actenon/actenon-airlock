"""A plain-language account of one consequential effect, built from signed evidence.

Every statement in the report comes from the project's verified receipt journal, the
candidate the agent produced, the owner-only provider observation that a signed
reconciliation binds by hash, or an independent readback the caller supplies. If the
journal does not verify, the report says so and claims nothing else.

The report never upgrades an outcome: an effect without a signed reconciliation is
reported as UNCONFIRMED, whatever the transport said.
"""

from __future__ import annotations

import hashlib
import json
import re

from .state import State

ACTION = "github.contents.write"
_SENT_STAGES = {"dispatched", "response-received", "execution-error"}


_HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def _diffstat(patch: bytes) -> list[dict]:
    """Per-file +/- counts of a unified diff, using hunk lengths so content lines that
    begin with '---' or '+++' are never mistaken for file headers."""
    files, current, old_left, new_left, removed_path = [], None, 0, 0, None
    for line in patch.decode("utf-8", "replace").splitlines():
        if old_left or new_left:
            if line.startswith("-"):
                current["removed"] += 1
                old_left -= 1
            elif line.startswith("+"):
                current["added"] += 1
                new_left -= 1
            elif not line.startswith("\\"):
                old_left, new_left = old_left - 1, new_left - 1
            continue
        if line.startswith("--- "):
            removed_path = line[4:].removeprefix("a/")
        elif line.startswith("+++ "):
            path = line[4:].removeprefix("b/")
            current = {
                "path": removed_path if path == "/dev/null" else path,
                "added": 0,
                "removed": 0,
            }
            files.append(current)
        elif current is not None and (match := _HUNK.match(line)):
            old_left = int(match.group(1) or 1)
            new_left = int(match.group(2) or 1)
    return files


def _observation(state: State, evidence_hash: str | None) -> dict | None:
    """The owner-only readback artifact whose hash a signed reconciliation names."""
    if not evidence_hash:
        return None
    for path in sorted(state.local.glob("github-observation-*.json")):
        body = path.read_bytes()
        if hashlib.sha256(body).hexdigest() == evidence_hash:
            data = json.loads(body)
            return {
                "path": str(path),
                "sha256": evidence_hash,
                "commit_sha": data.get("commit_sha"),
                "acknowledged_commit": data.get("acknowledged_commit"),
                "causal_attribution": data.get("causal_attribution"),
                "reason": data.get("reason"),
                "observation_kind": data.get("observation_kind"),
            }
    return {"path": None, "sha256": evidence_hash, "missing": True}


def _uncertain(sent, settled, outcome, observation, independent) -> list[str]:
    items = []
    if sent is None:
        items.append("No request for this effect was sent.")
    elif not settled:
        items.append(
            f"The outcome is {outcome or 'unknown'} and has NOT been settled by readback: "
            "do not assume the file exists or does not exist."
        )
    if sent is not None and observation and observation.get("acknowledged_commit") is None:
        items.append(
            "GitHub's acknowledgement of the write never arrived; the outcome was established "
            "only by reading the repository back."
        )
    if observation and observation.get("causal_attribution") == "not_proven":
        items.append(
            "Which process made the commit is not proven: Airlock relies on being the only "
            "writer to the reviewed branch during creation and readback (exclusive-writer "
            "assumption)."
        )
    if observation and observation.get("missing"):
        items.append("The readback observation named by the signed reconciliation is missing.")
    if independent is None:
        items.append("No independent readback was supplied; only Airlock's own readback exists.")
    elif not independent.get("confirmed"):
        items.append("The independent readback did NOT confirm the reviewed file and commit.")
    items.append("Passing the operator's tests is not proof that the change is correct or safe.")
    return items


def build_report(state: State, effect_id: str | None, *, independent=None, candidate=None) -> dict:
    verified = state.verify_receipts()
    public = state.path / "public-key.json"
    report = {
        "schema": "actenon-airlock/consequence-report/v1",
        "effect_id": effect_id,
        "journal": {
            "ok": verified["ok"],
            "receipts": verified["receipts"],
            "path": str(state.receipts_path),
            "public_key": str(public),
            "public_key_sha256": hashlib.sha256(public.read_bytes()).hexdigest(),
        },
    }
    if not verified["ok"]:
        report["status"] = "EVIDENCE_INVALID"
        report["headline"] = "The signed journal does not verify; nothing here can be relied on."
        return report
    rows = [item["row"] for item in verified["rows"]]
    effect_rows = [r for r in rows if effect_id and r.get("effect_id") == effect_id]
    sent = next((r for r in effect_rows if r.get("stage") in _SENT_STAGES), None)
    settled = [r for r in effect_rows if r.get("stage") == "reconciled"]
    settled = settled[-1] if settled else None
    profile = (sent or {}).get("github_profile", {})
    review = profile.get("review", {})
    content_sha = review.get("content_sha256") or candidate

    wanted = {"candidate_sha256": content_sha, "diffstat": []}
    candidate_dir = state.local / "candidates" / str(content_sha)
    if (candidate_dir / "candidate.json").is_file():
        meta = json.loads((candidate_dir / "candidate.json").read_text())
        wanted["changes"] = meta.get("changes", [])
        wanted["diffstat"] = _diffstat((candidate_dir / "candidate.patch").read_bytes())
        wanted["trust"] = meta.get("trust")
    tests = [
        r
        for r in rows
        if r.get("stage") == "candidate-tests" and r.get("candidate_sha256") == content_sha
    ]
    if tests:
        wanted["tests"] = {"verdict": tests[-1].get("verdict"), "meaning": tests[-1].get("meaning")}

    refused = [
        {
            "target": r.get("target"),
            "reason": r.get("reason"),
            "credential_released": r.get("credential_released"),
        }
        for r in rows
        if r.get("action") == ACTION and r.get("decision") == "DENY"
    ]
    payload = ((settled or {}).get("reconciliation") or {}).get("payload", {})
    observation = _observation(state, payload.get("evidence_hash"))
    outcome = (settled or {}).get("outcome") or (sent or {}).get("outcome")
    confirmed = bool(settled and outcome == "COMMITTED")
    independent_ok = bool(independent and independent.get("confirmed"))
    if confirmed and independent is not None and not independent_ok:
        status = "DISPUTED"
        headline = (
            "Airlock's readback says the file was created, but the independent readback "
            "disagrees. Treat the outcome as unconfirmed."
        )
    elif confirmed and independent_ok:
        status = "CONFIRMED"
        headline = (
            "Created exactly one reviewed file; confirmed by Airlock's readback and independently."
        )
    elif confirmed:
        status = "CONFIRMED_BY_AIRLOCK_READBACK"
        headline = "Created the reviewed file; confirmed by Airlock's own readback only."
    elif sent is not None:
        status, headline = "UNCONFIRMED", "A write was sent, but its outcome is not confirmed."
    else:
        status, headline = "NOT_SENT", "Nothing was sent to GitHub."

    report.update(
        status=status,
        headline=headline,
        wanted=wanted,
        authorised={
            **review,
            "credential_name": profile.get("credential_name"),
            "exclusive_writer": profile.get("exclusive_writer"),
            "approval_digest": (sent or {}).get("approval_digest"),
        },
        sent=None
        if sent is None
        else {
            "method": (sent.get("detail") or {}).get("method"),
            "target": sent.get("target"),
            "at": sent.get("timestamp"),
            "credential_released": sent.get("credential_released"),
            "preflight": [
                {"url": p.get("url"), "status": p.get("status")}
                for p in sent.get("github_preflight", [])
            ],
            "transport_outcome": sent.get("outcome"),
            "receipt_id": sent.get("id"),
        },
        airlock_readback=None
        if settled is None
        else {
            "outcome": settled.get("outcome"),
            "settled_at": settled.get("settled_at"),
            "evidence_source": settled.get("evidence_source"),
            "commit_sha": (observation or {}).get("commit_sha"),
            "observation": observation,
            "receipt_id": settled.get("id"),
        },
        independent_readback=independent,
        refused=refused,
        uncertain=_uncertain(sent, settled, outcome, observation, independent),
    )
    return report


def _code(value) -> str:
    return "`" + str(value) + "`" if value not in (None, "") else "—"


def render_markdown(report: dict) -> str:
    out = [f"# Consequence report: {report.get('status')}", "", f"**{report.get('headline')}**"]
    journal = report["journal"]
    if report.get("status") == "EVIDENCE_INVALID":
        return "\n".join([*out, "", f"Journal: {_code(journal['path'])}", ""])
    wanted, authorised = report["wanted"], report["authorised"]

    out += ["", "## 1. What the agent wanted to change", ""]
    out += [f"- `{c['path']}`: +{c['added']} / -{c['removed']} lines" for c in wanted["diffstat"]]
    out.append(
        f"- Exact patch SHA-256: {_code(wanted.get('candidate_sha256'))} "
        f"({wanted.get('trust') or 'untrusted agent output'})"
    )
    if wanted.get("tests"):
        tests = wanted["tests"]
        out.append(f"- Operator tests: **{tests['verdict']}** ({tests['meaning']})")

    out += ["", "## 2. What Airlock authorised", ""]
    if authorised.get("path"):
        out += [
            f"- Create **one new file** {_code(authorised['path'])} in "
            f"{_code(authorised['owner'] + '/' + authorised['repo'])}, branch "
            f"{_code(authorised['branch'])}",
            f"- Only on top of commit {_code(authorised['expected_parent_sha'])}, "
            "with exactly the patch above",
            f"- Commit message: {_code(authorised['message'])}",
            f"- Credential {_code(authorised['credential_name'])}, held by the supervisor only "
            f"(exclusive writer assumed: {_code(authorised['exclusive_writer'])})",
            f"- Signed approval digest: {_code(authorised['approval_digest'])}",
        ]
    else:
        out.append("- No GitHub creation was authorised for this effect.")

    out += ["", "## 3. What was actually sent", ""]
    sent = report.get("sent")
    if sent:
        checks = ", ".join(
            f"{p['url'].rsplit('/', 1)[-1]} -> HTTP {p['status']}" for p in sent["preflight"]
        )
        out += [
            f"- {sent['method']} {_code(sent['target'])} at {sent['at']}",
            f"- Checks before writing: {checks or 'none recorded'}",
            f"- Credential released for this request: {_code(sent['credential_released'])}",
            f"- What the transport alone established: **{sent['transport_outcome']}**",
        ]
    else:
        out.append("- Nothing.")

    out += ["", "## 4. What GitHub confirmed", ""]
    readback = report.get("airlock_readback")
    if readback:
        out.append(
            f"- Airlock's readback: **{readback['outcome']}** at {readback['settled_at']}, "
            f"commit {_code(readback['commit_sha'])}"
        )
    else:
        out.append("- Airlock's readback: **none yet. The outcome stays unconfirmed.**")
    independent = report.get("independent_readback")
    if independent:
        verdict = "confirmed" if independent["confirmed"] else "NOT confirmed"
        out.append(
            f"- Independent readback ({independent['source']}): **{verdict}**, "
            f"commit {_code(independent.get('commit_sha'))}"
        )
        out += [
            f"  - {name.replace('_', ' ')}: {'yes' if ok else '**NO**'}"
            for name, ok in independent["checks"].items()
        ]

    out += ["", "## 5. What was refused at the authority boundary", ""]
    out += [
        f"- {_code(r['target'])}: {r['reason']} (credential released: {r['credential_released']})"
        for r in report["refused"]
    ] or ["- Nothing."]

    out += ["", "## 6. What remains uncertain", ""]
    out += [f"- {item}" for item in report["uncertain"]]

    out += [
        "",
        "## 7. Inspect the signed evidence",
        "",
        f"- Journal: {_code(journal['path'])} ({journal['receipts']} receipts, "
        f"signatures verified: {journal['ok']})",
        f"- Public key: {_code(journal['public_key'])} "
        f"(SHA-256 {_code(journal['public_key_sha256'])}). Compare it with a copy you hold.",
        f"- Verify offline: `airlock verify-evidence --journal {journal['path']} "
        "--public-key <the key you obtained independently> --checkpoint <your checkpoint>`",
    ]
    observation = (readback or {}).get("observation") or {}
    if observation.get("path"):
        out.append(
            f"- Readback observation (owner-only; may contain private content): "
            f"{_code(observation['path'])}, bound by SHA-256 {_code(observation['sha256'])}"
        )
    return "\n".join(out) + "\n"
