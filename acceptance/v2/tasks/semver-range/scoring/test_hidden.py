from versionlib import Version, satisfies


def test_semver_spec_precedence_chain():
    chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
             "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]  # fmt: skip
    versions = [Version(v) for v in chain]
    for lower, higher in zip(versions, versions[1:], strict=False):
        assert lower < higher, (lower._key(), higher._key())


def test_numeric_identifiers_compare_numerically():
    assert Version("1.0.0-rc.2") < Version("1.0.0-rc.10")


def test_numeric_identifiers_rank_below_alphanumeric():
    assert Version("1.0.0-1") < Version("1.0.0-alpha")


def test_caret_on_zero_minor():
    assert satisfies("0.2.5", "^0.2.3")
    assert not satisfies("0.3.0", "^0.2.3")
    assert not satisfies("0.9.0", "^0.2.3")


def test_caret_on_zero_zero_patch():
    assert satisfies("0.0.3", "^0.0.3")
    assert not satisfies("0.0.4", "^0.0.3")


def test_caret_major():
    assert satisfies("1.9.9", "^1.2.3")
    assert not satisfies("2.0.0", "^1.2.3")
    assert not satisfies("1.2.2", "^1.2.3")


def test_tilde_unchanged():
    assert satisfies("1.2.9", "~1.2.3")
    assert not satisfies("1.3.0", "~1.2.3")


def test_equal_versions_hash_alike():
    assert len({Version("1.0.0-rc.1"), Version("1.0.0-rc.1")}) == 1
