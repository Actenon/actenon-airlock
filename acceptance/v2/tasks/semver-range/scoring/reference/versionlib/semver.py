import re
from functools import total_ordering

_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


def _identifier(part):
    return (0, int(part), "") if part.isdigit() else (1, 0, part)


@total_ordering
class Version:
    def __init__(self, text):
        match = _PATTERN.match(text)
        if not match:
            raise ValueError(f"invalid version: {text}")
        self.major, self.minor, self.patch = (int(match.group(i)) for i in (1, 2, 3))
        self.prerelease = match.group(4) or ""

    def _key(self):
        release = (self.major, self.minor, self.patch)
        if not self.prerelease:
            return (release, 1, ())
        return (release, 0, tuple(_identifier(p) for p in self.prerelease.split(".")))

    def __eq__(self, other):
        return self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())


def satisfies(version, spec):
    candidate = Version(version)
    if spec.startswith("^"):
        low = Version(spec[1:])
        if low.major:
            high = Version(f"{low.major + 1}.0.0")
        elif low.minor:
            high = Version(f"0.{low.minor + 1}.0")
        else:
            high = Version(f"0.0.{low.patch + 1}")
        return low <= candidate < high
    if spec.startswith("~"):
        low = Version(spec[1:])
        high = Version(f"{low.major}.{low.minor + 1}.0")
        return low <= candidate < high
    return candidate == Version(spec)
