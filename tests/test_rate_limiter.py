"""Regression tests for shared rate-limit storage."""

import asyncio
import os
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from starlette.requests import Request
from starlette.responses import Response

from decemsg.core.config import AppConfig, RateLimitConfig
import decemsg.core.rate_limiter as rate_limiter


def test_limiter_uses_configured_shared_storage(monkeypatch) -> None:
    """The application limiter must use its configured backend, not memory."""
    storage_uri = "redis://localhost:6379/15"
    config = AppConfig(
        rate_limit=RateLimitConfig(
            enabled=True,
            auth_rate="1/minute",
            federation_rate="1/minute",
            storage_uri=storage_uri,
        )
    )
    monkeypatch.setattr(rate_limiter, "get_config", lambda: config)

    limiter = rate_limiter.create_limiter()

    assert limiter.enabled is True
    assert limiter._storage_uri == storage_uri
    assert limiter._storage.__class__.__name__ == "RedisStorage"


def test_disabling_rate_limits_disables_route_decorators(monkeypatch) -> None:
    """The configuration switch disables both global and decorated limits."""
    config = AppConfig(
        rate_limit=RateLimitConfig(enabled=False, storage_uri="memory://")
    )
    monkeypatch.setattr(rate_limiter, "get_config", lambda: config)

    limiter = rate_limiter.create_limiter()

    assert limiter.enabled is False


@pytest.mark.security
def test_independent_limiters_share_redis_counters(monkeypatch) -> None:
    """Two independent app-worker limiter instances observe the same counter."""
    storage_uri = os.environ.get("DECEMSG_TEST_REDIS_URL")
    if not storage_uri:
        pytest.skip("Set DECEMSG_TEST_REDIS_URL to run the Redis integration test")

    config = AppConfig(
        rate_limit=RateLimitConfig(
            enabled=True,
            auth_rate="1/minute",
            federation_rate="1/minute",
            storage_uri=storage_uri,
        )
    )
    monkeypatch.setattr(rate_limiter, "get_config", lambda: config)

    worker_one = rate_limiter.create_limiter()
    worker_two = rate_limiter.create_limiter()
    key = f"task-023:{uuid4().hex}"

    try:
        assert worker_one._storage.incr(key, expiry=60) == 1
        assert worker_two._storage.get(key) == 1
        assert worker_two._storage.incr(key, expiry=60) == 2
        assert worker_one._storage.get(key) == 2
    finally:
        worker_one._storage.clear(key)

    # The same policy is enforced across independent limiter instances, not
    # only by the storage object's raw counter methods.
    client_host = f"task-023-{uuid4().hex}"
    first = rate_limiter.get_sensitive_rate_limit_response(
        _request("/federation/messages", client_host), worker_one
    )
    second = rate_limiter.get_sensitive_rate_limit_response(
        _request("/federation/receipts", client_host), worker_two
    )
    assert first is None
    assert second is not None
    assert second.status_code == 429


def _request(path: str, client_host: str = "192.0.2.30") -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "server": ("testserver", 80),
            "client": (client_host, 12345),
            "root_path": "",
        },
        receive,
    )


def test_auth_and_federation_paths_have_explicit_shared_limits(monkeypatch) -> None:
    """Sensitive route families are capped and share consistent 429 responses."""
    config = AppConfig(
        rate_limit=RateLimitConfig(
            enabled=True,
            auth_rate="1/minute",
            federation_rate="1/minute",
            storage_uri="memory://",
        )
    )
    monkeypatch.setattr(rate_limiter, "get_config", lambda: config)
    instance = rate_limiter.create_limiter()
    client_host = "192.0.2.31"

    assert rate_limiter.get_sensitive_rate_limit_response(
        _request("/api/auth/change-password", client_host), instance
    ) is None
    auth_limited = rate_limiter.get_sensitive_rate_limit_response(
        _request("/api/auth/sessions", client_host), instance
    )
    assert auth_limited is not None
    assert auth_limited.status_code == 429
    assert auth_limited.headers["Retry-After"]
    assert auth_limited.headers["X-RateLimit-Limit"] == "1"
    assert auth_limited.headers["X-RateLimit-Remaining"] == "0"
    assert b'"detail":"Rate limit exceeded. Please try again later."' in auth_limited.body

    # Federation has its own counter scope, and every federation route shares it.
    assert rate_limiter.get_sensitive_rate_limit_response(
        _request("/federation/messages", client_host), instance
    ) is None
    federation_limited = rate_limiter.get_sensitive_rate_limit_response(
        _request("/federation/receipts", client_host), instance
    )
    assert federation_limited is not None
    assert federation_limited.status_code == 429
    assert federation_limited.headers["Retry-After"] == auth_limited.headers["Retry-After"]
    assert federation_limited.headers["X-RateLimit-Limit"] == auth_limited.headers["X-RateLimit-Limit"]


def test_non_sensitive_routes_are_not_subject_to_sensitive_route_limit(monkeypatch) -> None:
    config = AppConfig(
        rate_limit=RateLimitConfig(enabled=True, storage_uri="memory://")
    )
    monkeypatch.setattr(rate_limiter, "get_config", lambda: config)
    instance = rate_limiter.create_limiter()

    assert rate_limiter.get_sensitive_rate_limit_response(
        _request("/api/chats"), instance
    ) is None


def test_disabled_rate_limiting_bypasses_sensitive_route_policy(monkeypatch) -> None:
    config = AppConfig(
        rate_limit=RateLimitConfig(enabled=False, storage_uri="memory://")
    )
    monkeypatch.setattr(rate_limiter, "get_config", lambda: config)
    instance = rate_limiter.create_limiter()

    for _ in range(2):
        assert rate_limiter.get_sensitive_rate_limit_response(
            _request("/federation/messages"), instance
        ) is None


@pytest.mark.security
def test_federation_middleware_limits_before_authentication(monkeypatch) -> None:
    """Missing-signature requests consume the shared federation budget first."""
    from decemsg.federation import auth_middleware as federation_auth

    config = AppConfig(
        rate_limit=RateLimitConfig(
            enabled=True,
            federation_rate="1/minute",
            storage_uri="memory://",
        )
    )
    monkeypatch.setattr(rate_limiter, "get_config", lambda: config)
    instance = rate_limiter.create_limiter()
    monkeypatch.setattr(
        federation_auth,
        "get_sensitive_rate_limit_response",
        lambda request: rate_limiter.get_sensitive_rate_limit_response(request, instance),
    )
    middleware = federation_auth.FederationAuthMiddleware(AsyncMock())
    call_next = AsyncMock(return_value=Response(status_code=204))
    host = f"task-023-auth-first-{uuid4().hex}"

    first = asyncio.run(
        middleware.dispatch(_request("/federation/messages", host), call_next)
    )
    second = asyncio.run(
        middleware.dispatch(_request("/federation/messages", host), call_next)
    )

    assert first.status_code == 401
    assert second.status_code == 429
    call_next.assert_not_awaited()
