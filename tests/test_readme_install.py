"""The README's install command must be one immutable commit of this repository.

A branch pin broke the documented install for every newcomer once the branch was deleted.
The network install itself runs in CI (``scripts/check_readme_install.py --install``).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_readme_install", ROOT / "scripts" / "check_readme_install.py"
)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

SHA = "c38093e8a521fac4f5dbeaef32eb454b989260d0"


def _readme(ref: str, url: str = check.REPO_URL) -> str:
    return f'~~~sh\npython -m pip install "git+{url}@{ref}"\nairlock doctor\n~~~\n'


def test_repository_readme_pins_one_full_commit():
    sha = check.check_readme((ROOT / "README.md").read_text(encoding="utf-8"))
    assert check.FULL_SHA.match(sha)


@pytest.mark.parametrize("ref", ["feat/protected-acceptance", "main", "v0.1.0", SHA[:12]])
def test_branch_tag_or_short_ref_is_rejected(ref):
    with pytest.raises(ValueError, match="full 40-character commit SHA"):
        check.check_readme(_readme(ref))


def test_missing_or_duplicate_install_command_is_rejected():
    with pytest.raises(ValueError, match="found 0"):
        check.check_readme("no install here")
    with pytest.raises(ValueError, match="found 2"):
        check.check_readme(_readme(SHA) + _readme(SHA))


def test_install_from_another_repository_is_rejected():
    with pytest.raises(ValueError, match="not https://github.com/Actenon/actenon-airlock.git"):
        check.check_readme(_readme(SHA, url="https://github.com/someone/fork.git"))


def test_full_sha_of_this_repository_is_accepted():
    assert check.check_readme(_readme(SHA)) == SHA
