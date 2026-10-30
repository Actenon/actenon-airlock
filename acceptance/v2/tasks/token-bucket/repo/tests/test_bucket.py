import time

import pytest
from ratelimit import TokenBucket


def test_initial_burst_within_capacity():
    bucket = TokenBucket(capacity=5, fill_rate=10.0)
    for _ in range(5):
        assert bucket.consume(1) is True
    assert bucket.consume(1) is False


def test_rejects_non_positive_tokens():
    bucket = TokenBucket(capacity=5, fill_rate=10.0)
    with pytest.raises(ValueError):
        bucket.consume(0)


def test_rapid_polling_still_refills():
    bucket = TokenBucket(capacity=5, fill_rate=10.0)
    for _ in range(5):
        bucket.consume(1)
    replenished = 0
    for _ in range(20):
        time.sleep(0.03)
        if bucket.consume(1):
            replenished += 1
    assert replenished >= 4, f"expected at least 4 refilled tokens, got {replenished}"
