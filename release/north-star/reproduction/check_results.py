#!/usr/bin/env python3
"""Compare a reproduction run with expected.json. Standard library only; imports nothing from Airlock.

Subcommands (each prints one JSON object and exits 1 on any mismatch):

  identity CLONE                 commit and source digest of the candidate clone
  junit CLONE NAME XML [XML...]  test outcomes against the candidate's own CI contract (release/gates.json)
  journals RESULTS               independent-verifier output against the expected journal list
  provider CLONE                 published provider observations agree with the reviewed bytes
  installed SITE_PACKAGES        installed dependency commits (direct_url.json) against expected.json
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE / "expected.json").read_text())


def out(name: str, ok: bool, **facts) -> int:
    print(json.dumps({"check": name, "ok": ok, **facts}, indent=2))
    return 0 if ok else 1


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def source_digest(repo: Path, ref: str = "HEAD") -> tuple[str, int]:
    """sha256(sorted package-relative path + NUL + bytes) over src/actenon_airlock, from Git objects."""
    prefix = "src/actenon_airlock/"
    entries = git(repo, "ls-tree", "-rz", ref, "--", prefix).split(b"\0")
    payloads = {}
    for entry in entries:
        if not entry:
            continue
        header, path = entry.split(b"\t", 1)
        mode, kind, blob = header.decode().split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"unsupported entry {path!r}")
        payloads[path.decode().removeprefix(prefix)] = git(repo, "cat-file", "blob", blob)
    digest = hashlib.sha256()
    for name in sorted(payloads):
        digest.update(name.encode() + b"\0" + payloads[name])
    return digest.hexdigest(), len(payloads)


def identity(clone: str) -> int:
    repo = Path(clone)
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    digest, files = source_digest(repo)
    want = EXPECTED["candidate"]
    return out("identity", commit == want["commit"] and digest == want["source_digest"],
               commit=commit, expected_commit=want["commit"], source_digest=digest,
               expected_source_digest=want["source_digest"], files=files)  # fmt: skip


def outcomes(xml_path: str) -> dict[str, str]:
    root = ET.parse(xml_path).getroot()
    result = {}
    for case in root.iter("testcase"):
        name = f"{case.get('classname')}::{case.get('name')}"
        if case.find("failure") is not None or case.find("error") is not None:
            result[name] = "failed"
        elif case.find("skipped") is not None:
            result[name] = "skipped"
        else:
            result[name] = "passed"
    return result


def junit(clone: str, artifact: str, *files: str) -> int:
    """Check reports the way the release gate does, using the candidate's committed contract."""
    contract = json.loads((Path(clone) / "release" / "gates.json").read_text())["ci_prerequisites"]
    problems, summary = [], {}
    wanted = {r["file"] for r in contract["junit"] if r["artifact"] == artifact}
    given = {Path(f).name for f in files}
    if not wanted:
        problems.append(f"{artifact}: not an artifact in the CI contract")
    for name in sorted(wanted - given):
        problems.append(f"{artifact}: contract report {name} was not supplied")
    for path in files:
        name = Path(path).name
        spec = next((r for r in contract["junit"] if r["artifact"] == artifact and r["file"] == name), None)
        if spec is None:
            problems.append(f"{name}: not in the CI contract for {artifact}")
            continue
        got = outcomes(path)
        failed = sorted(n for n, o in got.items() if o == "failed")
        skipped = {n for n, o in got.items() if o == "skipped"}
        unexpected = sorted(skipped - set(spec["allowed_skips"]))
        missing = sorted(n for n in spec["must_pass"] if got.get(n) != "passed")
        summary[name] = {"cases": len(got), "failed": len(failed), "skipped": len(skipped),
                         "unexpected_skips": unexpected[:10], "required_not_passed": missing[:10]}  # fmt: skip
        if failed:
            problems.append(f"{name}: {len(failed)} failed, e.g. {failed[:3]}")
        if unexpected:
            problems.append(f"{name}: skips the contract does not allow, e.g. {unexpected[:3]}")
        if missing:
            problems.append(f"{name}: required tests that did not pass, e.g. {missing[:3]}")
    return out(f"junit:{artifact}", not problems, reports=summary, problems=problems)


def journals(results: str) -> int:
    want = {j["journal"]: j for j in EXPECTED["journals"]}
    got, problems = {}, []
    for line in Path(results).read_text().splitlines():
        body, _, code = line.rpartition(" EXIT=")
        try:
            report = json.loads(body)
        except ValueError:
            problems.append(f"unreadable verifier output: {line[:80]}")
            continue
        got[report["journal"]] = report
        exp = want.get(report["journal"])
        if exp is None:
            problems.append(f"{report['journal']}: not an expected journal")
            continue
        for key in ("entries", "chain_head_sha256", "completeness"):
            if report[key] != exp[key]:
                problems.append(f"{report['journal']}: {key} {report[key]!r} != expected {exp[key]!r}")
        if not report["integrity_ok"] or code.strip() != "0":
            problems.append(f"{report['journal']}: integrity failed")
    for path in sorted(set(want) - set(got)):
        problems.append(f"{path}: expected journal was not verified")
    entries = sum(r["entries"] for r in got.values())
    return out("journals", not problems, journals=len(got), receipts=entries, problems=problems[:20],
               provider_truth="NOT established by journal verification; see the provider check")  # fmt: skip


def provider(clone: str) -> int:
    """Gate 6 (historical): the reviewed bytes, Airlock's readback and the separate-token readback agree."""
    base = Path(clone) / "release/gate5-rerun-gate6/live/gate6"
    reviewed = json.loads((base / "reviewed-create.json").read_text())["review"]
    owner = json.loads((base / "owner-readback.json").read_text())
    airlock = json.loads((base / "airlock-readback-observation.sanitised.json").read_text())
    checks = {
        "owner_readback_bytes_match_review": owner["file"]["content_sha256"] == reviewed["content_sha256"],
        "owner_readback_path_matches_review": owner["file"]["path"] == reviewed["path"],
        "owner_readback_repo_matches_review": owner["repository"]["id"] == reviewed["repo_id"],
        "airlock_readback_bytes_match_review": airlock["creation"]["content_sha256"] == reviewed["content_sha256"],
        "both_readbacks_name_the_same_commit": airlock["commit_sha"] == owner["commit"]["sha"],
        "airlock_outcome": airlock["outcome"] == "COMMITTED",
    }
    return out("provider:gate6-historical", all(checks.values()), checks=checks,
               limitation="Offline consistency of published records only. The repository is private, so "
                          "an operator cannot read GitHub's state directly; that needs read access granted "
                          "by the owner.")  # fmt: skip


def installed(site: str) -> int:
    want, got, problems = EXPECTED["dependencies"], {}, []
    for meta in Path(site).glob("actenon_*.dist-info/direct_url.json"):
        name = meta.parent.name.split("-")[0].replace("_", "-")
        got[name] = (json.loads(meta.read_text()).get("vcs_info") or {}).get("commit_id")
    for name, commit in want.items():
        if got.get(name) != commit:
            problems.append(f"{name}: installed {got.get(name)} != expected {commit}")
    return out("installed-dependencies", not problems, installed=got, problems=problems)


if __name__ == "__main__":
    command, *args = sys.argv[1:] or ["help"]
    commands = {"identity": identity, "junit": junit, "journals": journals, "provider": provider,
                "installed": installed}  # fmt: skip
    if command not in commands:
        print(__doc__)
        sys.exit(2)
    sys.exit(commands[command](*args))
