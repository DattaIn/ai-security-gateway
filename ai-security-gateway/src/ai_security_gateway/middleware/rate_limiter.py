"""Sliding-window rate limiter.

In-memory implementation for the reference/demo deployment. The
interface is deliberately narrow (`allow(client_id) -> bool`) so a
production deployment can swap in a Redis- or Envoy-backed limiter
without touching the gateway logic.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: float = 0.0


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, client_id: str) -> RateLimitDecision:
        now = time.monotonic()
        window_start = now - self.window_seconds
        q = self._hits[client_id]

        while q and q[0] < window_start:
            q.popleft()

        if len(q) >= self.max_requests:
            retry_after = self.window_seconds - (now - q[0])
            return RateLimitDecision(allowed=False, remaining=0, retry_after_seconds=max(retry_after, 0.0))

        q.append(now)
        return RateLimitDecision(allowed=True, remaining=self.max_requests - len(q))
