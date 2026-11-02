"""Problem setup and test fixtures for Actenon Field Test 6."""

from pathlib import Path

BUGGY_RATE_LIMITER = '''import time

class TokenBucket:
    """Token bucket rate limiter with a subtle fractional replenishment bug."""

    def __init__(self, capacity: int, fill_rate: float):
        """
        capacity: Maximum tokens the bucket can hold.
        fill_rate: Tokens added per second.
        """
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = float(capacity)
        self.last_update = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        now = time.monotonic()
        elapsed = now - self.last_update
        # DEFECT: Unconditionally updating last_update on every call resets the clock
        # before fractional tokens can accumulate, while integer truncation drops fractions.
        # Rapid polling permanently starves the bucket.
        self.last_update = now
        added = int(elapsed * self.fill_rate)
        if added > 0:
            self.tokens = min(float(self.capacity), self.tokens + added)
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
'''

WORKSPACE_TESTS = '''import time
import pytest
from rate_limiter import TokenBucket

def test_initial_burst_within_capacity():
    bucket = TokenBucket(capacity=5, fill_rate=10.0)
    for _ in range(5):
        assert bucket.consume(1) is True
    assert bucket.consume(1) is False

def test_reject_zero_and_negative_tokens():
    bucket = TokenBucket(capacity=5, fill_rate=10.0)
    with pytest.raises(ValueError):
        bucket.consume(0)
    with pytest.raises(ValueError):
        bucket.consume(-1)

def test_rapid_fractional_refill():
    """Fails on buggy integer truncation under rapid polling."""
    bucket = TokenBucket(capacity=5, fill_rate=10.0)
    for _ in range(5):
        assert bucket.consume(1) is True
    assert bucket.consume(1) is False

    # Poll every 30ms over 600ms total.
    # At fill_rate=10.0 tokens/sec, 600ms generates ~6 tokens.
    # Buggy code computes int(0.03 * 10) = 0 and starves.
    replenished = 0
    for _ in range(20):
        time.sleep(0.03)
        if bucket.consume(1):
            replenished += 1
    assert replenished >= 4, f"Expected >= 4 replenished tokens, got {replenished}"
'''

INDEPENDENT_VERIFICATION_TESTS = '''import time
import pytest
from rate_limiter import TokenBucket

def test_sustained_steady_stream():
    """Independent verification: verifies steady 10 tokens/sec stream."""
    bucket = TokenBucket(capacity=10, fill_rate=20.0)
    # Drain initial capacity
    for _ in range(10):
        assert bucket.consume(1) is True
    assert bucket.consume(1) is False

    # Wait 0.25s -> should replenish ~5 tokens
    time.sleep(0.25)
    consumed = 0
    for _ in range(10):
        if bucket.consume(1):
            consumed += 1
    assert 4 <= consumed <= 6, f"Expected ~5 tokens, got {consumed}"

def test_refill_caps_at_capacity():
    """Independent verification: bucket does not overflow past capacity."""
    bucket = TokenBucket(capacity=5, fill_rate=100.0)
    time.sleep(0.1)  # Would generate 10 tokens, but capacity is 5
    consumed = 0
    while bucket.consume(1):
        consumed += 1
    assert consumed == 5, f"Expected exactly capacity (5), got {consumed}"

def test_large_single_consumption():
    """Independent verification: bucket allows large token chunks if available."""
    bucket = TokenBucket(capacity=10, fill_rate=10.0)
    assert bucket.consume(7) is True
    assert bucket.consume(4) is False
    assert bucket.consume(3) is True
    assert bucket.consume(1) is False
'''

def setup_workspace(dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "rate_limiter.py").write_text(BUGGY_RATE_LIMITER)
    (dest / "test_rate_limiter.py").write_text(WORKSPACE_TESTS)

def setup_independent_tests(dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "test_independent_verification.py").write_text(INDEPENDENT_VERIFICATION_TESTS)
