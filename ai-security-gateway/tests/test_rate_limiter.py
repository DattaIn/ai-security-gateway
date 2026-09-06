from ai_security_gateway.middleware.rate_limiter import SlidingWindowRateLimiter


def test_allows_up_to_limit():
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        decision = limiter.allow("client-a")
        assert decision.allowed is True
    blocked = limiter.allow("client-a")
    assert blocked.allowed is False
    assert blocked.retry_after_seconds > 0


def test_clients_are_isolated():
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60)
    assert limiter.allow("client-a").allowed is True
    assert limiter.allow("client-b").allowed is True
    assert limiter.allow("client-a").allowed is False
