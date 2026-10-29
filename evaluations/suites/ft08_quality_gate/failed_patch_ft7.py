import time

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
        elapsed = max(0, now - self.last_update)
        # Correctly update last_update only if tokens are consumed
        # before fractional tokens can accumulate, while integer truncation drops fractions.
        # Rapid polling permanently starves the bucket.
        self.last_update = now
        added = int(elapsed * self.fill_rate)
        if added > 0:
                self.tokens += min(added, self.capacity - self.tokens)
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
