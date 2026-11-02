"""Correct TokenBucket implementation for Actenon Field Test 8 Positive Control."""

import time

class TokenBucket:
    """Token bucket rate limiter with correct fractional replenishment."""

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
        elapsed = max(0.0, now - self.last_update)
        self.last_update = now
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.fill_rate)
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
