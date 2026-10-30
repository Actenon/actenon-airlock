import time
from collections import OrderedDict


class TTLCache:
    """Bounded cache with least-recently-used eviction and per-entry expiry."""

    def __init__(self, maxsize, ttl, clock=time.monotonic):
        if maxsize <= 0:
            raise ValueError("maxsize must be positive")
        self.maxsize = maxsize
        self.ttl = ttl
        self.clock = clock
        self._items = OrderedDict()

    def set(self, key, value):
        if key in self._items:
            del self._items[key]
        elif len(self._items) >= self.maxsize:
            self._items.popitem(last=False)
        self._items[key] = (value, self.clock() + self.ttl)

    def get(self, key, default=None):
        entry = self._items.get(key)
        if entry is None:
            return default
        value, expires = entry
        if expires <= self.clock():
            return default
        return value

    def __len__(self):
        return len(self._items)

    def __contains__(self, key):
        return self.get(key, _MISSING) is not _MISSING


_MISSING = object()
