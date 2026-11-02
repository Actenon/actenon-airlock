import time


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, capacity: int, fill_rate: float):
        """capacity: maximum tokens held. fill_rate: tokens added per second."""
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = float(capacity)
        self.last_update = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now
        added = int(elapsed * self.fill_rate)
        if added > 0:
            self.tokens = min(float(self.capacity), self.tokens + added)
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
