import time


class TokenBucket:
    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = float(capacity)
        self.last_update = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        now = time.monotonic()
        self.tokens = min(
            float(self.capacity), self.tokens + (now - self.last_update) * self.fill_rate
        )
        self.last_update = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
