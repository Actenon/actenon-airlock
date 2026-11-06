from versionlib import Version, satisfies


def test_plain_ordering():
    assert Version("1.2.3") < Version("1.10.0")


def test_exact_spec():
    assert satisfies("1.2.3", "1.2.3")


def test_prerelease_sorts_before_its_release():
    assert Version("1.0.0-alpha") < Version("1.0.0")
