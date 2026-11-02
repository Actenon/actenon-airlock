import time
from collections import OrderedDict


class TTLCache:
    def __init__(self, maxsize, ttl, clock=time.monotonic):
        if maxsize <= 0:
            raise ValueError("maxsize must be positive")
        self.maxsize = maxsize
        self.ttl = ttl
        self.clock = clock
        self._items = OrderedDict()

    def _purge(self):
        now = self.clock()
        for key in [k for k, (_, expires) in self._items.items() if expires <= now]:
            del self._items[key]

    def set(self, key, value):
        self._purge()
        if key in self._items:
            del self._items[key]
        elif len(self._items) >= self.maxsize:
            self._items.popitem(last=False)
        self._items[key] = (value, self.clock() + self.ttl)

    def get(self, key, default=None):
        self._purge()
        if key not in self._items:
            return default
        self._items.move_to_end(key)
        return self._items[key][0]

    def __len__(self):
        self._purge()
        return len(self._items)

    def __contains__(self, key):
        return self.get(key, _MISSING) is not _MISSING


_MISSING = object()
