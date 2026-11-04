"""Reproduce the frozen runner's source digest from Git objects, without imports.

Default also proves that the runtime source tree contains exactly those bytes.
No environment variables, credentials, response data or git remote URLs are read.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def identity(repo, ref="HEAD", *, git_only=False):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args])

    commit = git("rev-parse", "--verify", ref + "^{commit}").decode().strip()
    prefix = "src/actenon_airlock/"
    entries = git("ls-tree", "-rz", commit, "--", prefix).split(b"\0")
    files, payloads = [], {}
    for entry in entries:
        if not entry:
            continue
        header, path = entry.split(b"\t", 1)
        mode, kind, blob = header.decode().split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("Unsupported source tree entry")
        name = path.decode().removeprefix(prefix)
        payload = git("cat-file", "blob", blob)
        payloads[name] = payload
        files.append(
            {
                "path": name,
                "mode": mode,
                "git_blob": blob,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if not files:
        raise ValueError("Source tree is empty")
    digest = hashlib.sha256()
    for name in sorted(payloads):
        digest.update(name.encode() + b"\0" + payloads[name])
    if not git_only:
        root = Path(repo) / prefix
        actual = {
            str(path.relative_to(root)): path
            for path in root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        }
        if set(actual) != set(payloads):
            raise ValueError("Runtime source inventory differs from Git")
        if any(
            path.is_symlink() or path.read_bytes() != payloads[name]
            for name, path in actual.items()
        ):
            raise ValueError("Runtime source bytes differ from Git")
    return {
        "schema": "actenon-airlock/source-identity/v1",
        "commit": commit,
        "algorithm": "sha256(sorted package-relative UTF-8 path + NUL + raw file bytes)",
        "scope": prefix.rstrip("/"),
        "source_digest": digest.hexdigest(),
        "runtime_matches_git": None if git_only else True,
        "files": sorted(files, key=lambda row: row["path"]),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--git-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(identity(args.repo, args.ref, git_only=args.git_only), indent=2))
