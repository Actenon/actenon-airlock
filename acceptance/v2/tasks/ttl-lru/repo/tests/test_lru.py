from cachekit import TTLCache


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_basic_set_and_get():
    cache = TTLCache(maxsize=2, ttl=10, clock=Clock())
    cache.set("a", 1)
    assert cache.get("a") == 1
    assert cache.get("missing", "fallback") == "fallback"


def test_recently_read_key_survives_eviction():
    cache = TTLCache(maxsize=2, ttl=100, clock=Clock())
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") == 1
    cache.set("c", 3)
    assert "a" in cache
    assert "b" not in cache
