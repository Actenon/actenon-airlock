from cachekit import TTLCache


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_get_refreshes_recency():
    cache = TTLCache(maxsize=2, ttl=100, clock=Clock())
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")
    cache.set("c", 3)
    assert cache.get("a") == 1 and cache.get("b") is None and cache.get("c") == 3


def test_expired_entries_are_not_counted():
    clock = Clock()
    cache = TTLCache(maxsize=3, ttl=10, clock=clock)
    cache.set("a", 1)
    cache.set("b", 2)
    clock.now = 11
    assert len(cache) == 0


def test_expired_entry_is_reclaimed_before_a_live_one():
    clock = Clock()
    cache = TTLCache(maxsize=2, ttl=10, clock=clock)
    cache.set("old", 1)
    clock.now = 6
    cache.set("live", 2)
    clock.now = 11  # "old" expired at 10; "live" expires at 16
    cache.set("new", 3)
    assert cache.get("live") == 2 and cache.get("new") == 3


def test_overwrite_resets_expiry_and_recency():
    clock = Clock()
    cache = TTLCache(maxsize=2, ttl=10, clock=clock)
    cache.set("a", 1)
    cache.set("b", 2)
    clock.now = 5
    cache.set("a", 9)
    clock.now = 12
    assert cache.get("a") == 9 and cache.get("b") is None


def test_maxsize_is_never_exceeded():
    cache = TTLCache(maxsize=3, ttl=100, clock=Clock())
    for i in range(50):
        cache.set(i, i)
    assert len(cache) == 3
