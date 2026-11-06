"""Every documented install command must be the same immutable commit of this repository.

A branch pin broke the documented install for every newcomer once the branch was deleted,
and a second guide once installed a different, older branch than the README described.
The network install itself runs in CI (``scripts/check_readme_install.py --install --demo``).
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_readme_install", ROOT / "scripts" / "check_readme_install.py"
)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

SHA = "c38093e8a521fac4f5dbeaef32eb454b989260d0"
OTHER = "a6ddd36c4d20d2dc9f6a11b0b895a34f40e52fd6"


def _doc(ref: str, url: str = check.REPO_URL, tool: str = "pipx install") -> str:
    return f'~~~sh\n{tool} "git+{url}@{ref}"\nairlock doctor\n~~~\n'


def test_the_repository_docs_pin_one_commit_that_installs_this_code():
    sha = check.check_documents()
    assert check.FULL_SHA.match(sha)
    shallow = check._git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"
    present = check._git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0
    if shallow and not present:
        pytest.skip("the pinned commit is outside this shallow clone; documented-install runs it")
    check.check_commit_in_history(sha)
    check.check_same_product(sha)


@pytest.mark.parametrize(
    "ref", ["feat/protected-acceptance", "main", "v0.1.0", SHA[:12], "AIRLOCK_COMMIT"]
)
def test_branch_tag_short_ref_or_placeholder_is_rejected(ref):
    with pytest.raises(ValueError, match="full 40-character commit SHA"):
        check.check_readme(_doc(ref))


def test_missing_install_command_is_rejected():
    with pytest.raises(ValueError, match="found 0"):
        check.check_readme("no install here")


def test_pipx_and_venv_forms_must_agree():
    both = _doc(SHA) + _doc(SHA, tool="~/.airlock/bin/pip install")
    assert check.check_readme(both) == SHA
    with pytest.raises(ValueError, match="different commits"):
        check.check_readme(_doc(SHA) + _doc(OTHER, tool="pip install"))


def test_install_from_another_repository_is_rejected():
    with pytest.raises(ValueError, match="not https://github.com/Actenon/actenon-airlock.git"):
        check.check_readme(_doc(SHA, url="https://github.com/someone/fork.git"))


def _tree(tmp_path: Path, readme: str, **docs: str) -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(readme)
    for name, text in docs.items():
        (tmp_path / "docs" / f"{name}.md").write_text(text)
    return tmp_path


def test_a_guide_that_installs_another_commit_is_rejected(tmp_path):
    root = _tree(tmp_path, _doc(SHA), guide=_doc(OTHER))
    with pytest.raises(ValueError, match="different commits"):
        check.check_documents(root)


def test_a_guide_with_an_unrecognised_install_form_is_rejected(tmp_path):
    root = _tree(
        tmp_path, _doc(SHA), guide=f"pip3 install git+{check.REPO_URL}@feat/airlock-north-star\n"
    )
    with pytest.raises(ValueError, match="guide.md: 1 install reference"):
        check.check_documents(root)


def test_a_checkout_of_another_commit_is_rejected(tmp_path):
    root = _tree(tmp_path, _doc(SHA), guide=f"git clone x && git checkout {OTHER}\n")
    with pytest.raises(ValueError, match="different commits"):
        check.check_documents(root)


def test_historical_evidence_is_never_checked_or_rewritten(tmp_path):
    root = _tree(tmp_path, _doc(SHA))
    (root / "docs" / "evidence").mkdir()
    old = root / "docs" / "evidence" / "run.md"
    old.write_text(_doc("feat/old-branch"))
    assert check.check_documents(root) == SHA
    check.pin(OTHER, root)
    assert "feat/old-branch" in old.read_text()
    assert check.check_documents(root) == OTHER


def test_pin_rewrites_every_form_and_the_placeholder(tmp_path):
    root = _tree(
        tmp_path,
        _doc("AIRLOCK_COMMIT") + _doc("AIRLOCK_COMMIT", tool="~/.airlock/bin/pip install"),
        guide=_doc("feat/x") + "git checkout AIRLOCK_COMMIT\n",
    )
    check.pin(SHA, root)
    assert check.check_documents(root) == SHA
    assert "AIRLOCK_COMMIT" not in (root / "docs" / "guide.md").read_text()


def test_an_older_product_commit_is_rejected():
    """Pinning a commit whose code differs from this checkout fails with the fix to run."""
    older = subprocess.run(
        ["git", "log", "--format=%H", "-2", "HEAD", "--", *check.INSTALLABLE],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()  # fmt: skip
    if len(older) < 2:
        pytest.skip("needs history with two product commits")
    with pytest.raises(ValueError, match="installs different code.*--pin"):
        check.check_same_product(older[1])
