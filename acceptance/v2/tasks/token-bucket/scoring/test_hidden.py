import time

from ratelimit import TokenBucket


def test_sustained_stream_rate():
    bucket = TokenBucket(capacity=10, fill_rate=20.0)
    for _ in range(10):
        assert bucket.consume(1)
    assert not bucket.consume(1)
    time.sleep(0.25)
    consumed = sum(1 for _ in range(10) if bucket.consume(1))
    assert 4 <= consumed <= 6


def test_refill_caps_at_capacity():
    bucket = TokenBucket(capacity=5, fill_rate=100.0)
    time.sleep(0.1)
    consumed = 0
    while bucket.consume(1):
        consumed += 1
    assert consumed == 5


def test_rapid_polling_with_low_rate_accumulates_fractions():
    bucket = TokenBucket(capacity=2, fill_rate=4.0)
    bucket.consume(2)
    admitted = 0
    for _ in range(60):
        time.sleep(0.01)
        if bucket.consume(1):
            admitted += 1
    assert 1 <= admitted <= 4


def test_multi_token_request_waits_for_enough_tokens():
    bucket = TokenBucket(capacity=4, fill_rate=10.0)
    bucket.consume(4)
    assert not bucket.consume(3)
    time.sleep(0.4)
    assert bucket.consume(3)
