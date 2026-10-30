import re
from functools import total_ordering

_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


@total_ordering
class Version:
    def __init__(self, text):
        match = _PATTERN.match(text)
        if not match:
            raise ValueError(f"invalid version: {text}")
        self.major, self.minor, self.patch = (int(match.group(i)) for i in (1, 2, 3))
        self.prerelease = match.group(4) or ""

    def _key(self):
        return (self.major, self.minor, self.patch, self.prerelease)

    def __eq__(self, other):
        return self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())


def satisfies(version, spec):
    """Return True if version matches a spec such as ^1.2.3, ~1.2.3 or 1.2.3."""
    candidate = Version(version)
    if spec.startswith("^"):
        low = Version(spec[1:])
        high = Version(f"{low.major + 1}.0.0")
        return low <= candidate < high
    if spec.startswith("~"):
        low = Version(spec[1:])
        high = Version(f"{low.major}.{low.minor + 1}.0")
        return low <= candidate < high
    return candidate == Version(spec)
