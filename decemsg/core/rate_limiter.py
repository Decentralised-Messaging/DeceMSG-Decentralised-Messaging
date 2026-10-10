"""DeceMSG rate limiting module."""
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse

from decemsg.core.config import get_config


def get_rate_limit_key(request: Request) -> str:
    """Get rate limit key based on client IP or user."""
    # Check if user is authenticated
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        # Use token hash as key for authenticated users
        from decemsg.core.auth import decode_token
        try:
            payload = decode_token(token)
            user_id = payload.get("sub")
            if user_id:
                return f"user:{user_id}"
        except Exception:
            pass
    
    # Fall back to IP address
    return get_remote_address(request)


def create_limiter() -> Limiter:
    """Create rate limiter instance."""
    config = get_config()
    
    if not config.rate_limit.enabled:
        # Disable both global and route-specific decorators.
        return Limiter(key_func=get_rate_limit_key, default_limits=[], enabled=False)

    return Limiter(
        key_func=get_rate_limit_key,
        default_limits=[config.rate_limit.api_rate],
        storage_uri=config.rate_limit.storage_uri,
    )


# Create global limiter instance
limiter = create_limiter()


def _rate_limit_error_response(retry_after: int | str, limit: int | str) -> JSONResponse:
    """Build the consistent 429 response used by decorators and middleware."""
    retry_after_text = str(retry_after)
    response = JSONResponse(
        status_code=429,
        content={
            "detail": "Rate limit exceeded. Please try again later.",
            "retry_after": retry_after_text,
        },
        headers={
            "Retry-After": retry_after_text,
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": "0",
        },
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data: blob:; connect-src 'self' ws: wss:; "
        "font-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self';",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Handle rate limit exceeded errors with the shared response format."""
    current = getattr(request.state, "view_rate_limit", None)
    if current:
        item = current[0]
        return _rate_limit_error_response(item.get_expiry(), item.amount)
    return _rate_limit_error_response(60, "unknown")


def get_login_rate_limit() -> str:
    """Get login rate limit from config."""
    config = get_config()
    return config.rate_limit.login_rate


def get_api_rate_limit() -> str:
    """Get API rate limit from config."""
    config = get_config()
    return config.rate_limit.api_rate


def get_sensitive_rate_limit_response(
    request: Request,
    limiter_instance: Limiter | None = None,
) -> JSONResponse | None:
    """Enforce shared per-IP limits for auth and federation route families.

    This covers routes that do not use SlowAPI decorators as well, including
    federation ingress behind its signature-authentication middleware.
    Storage errors fail closed with 503 rather than silently switching to local
    counters and bypassing the configured shared limit.
    """
    from limits import parse_many
    import logging

    config = get_config()
    active_limiter = limiter_instance or limiter
    if not config.rate_limit.enabled or not active_limiter.enabled:
        return None

    path = request.url.path
    if path.startswith("/api/auth/"):
        scope = "auth"
        limit_text = config.rate_limit.auth_rate
    elif path.startswith("/federation/"):
        scope = "federation"
        limit_text = config.rate_limit.federation_rate
    else:
        return None

    client_host = request.client.host if request.client else "unknown"
    identifier = f"decemsg:{scope}:{client_host}"

    try:
        for item in parse_many(limit_text):
            if not active_limiter.limiter.hit(item, identifier):
                return _rate_limit_error_response(item.get_expiry(), item.amount)
    except Exception:
        logging.getLogger(__name__).exception(
            "Shared rate-limit storage failed for scope %s", scope
        )
        response = JSONResponse(
            status_code=503,
            content={"detail": "Rate limiting service unavailable."},
            headers={"Retry-After": "60"},
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data: blob:; connect-src 'self' ws: wss:; "
            "font-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self';",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    return None
