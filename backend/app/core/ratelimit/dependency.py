"""Wiring the limiter into FastAPI.

One module so the handlers stay readable and so a test can override the store
in the same way it overrides the database.

The refusal is a **429 with `Retry-After`**, and its body is identical whatever
was attempted. That matters more than it looks: a 429 whose text differed
between a real and a non-existent account would turn the rate limiter into the
account-enumeration oracle that the login handler is careful not to be.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from app.core.config import get_settings
from app.core.ratelimit.contract import Decision
from app.core.ratelimit.keys import client_ip as derive_client_ip
from app.core.ratelimit.policy import RateLimiter
from app.core.ratelimit.stores import MemoryStore, RedisStore

#: Built once per process. The Redis client inside it is lazy and reconnects,
#: and the counters are Redis's, so sharing one instance is safe and avoids
#: opening a connection per request.
_store: RedisStore | MemoryStore | None = None


def get_store() -> RedisStore | MemoryStore:
    """The process-wide store. Overridden in tests via FastAPI dependencies."""
    global _store
    if _store is None:
        _store = RedisStore()
    return _store


def reset_store_for_tests(store: RedisStore | MemoryStore | None = None) -> None:
    global _store
    _store = store


def request_client_ip(request: Request) -> str:
    settings = get_settings()
    return derive_client_ip(
        socket_ip=request.client.host if request.client else None,
        forwarded_for=request.headers.get("X-Forwarded-For"),
        trusted_proxy_count=settings.trusted_proxy_count,
    )


def limiter(store: RedisStore | MemoryStore | None = None) -> RateLimiter:
    settings = get_settings()
    return RateLimiter(store or get_store(), pepper=settings.effective_rate_limit_pepper)


async def enforce(
    request: Request,
    route: str,
    *,
    identity: str | None = None,
    store: RedisStore | MemoryStore | None = None,
) -> Decision:
    """Consume budget and raise 429 if the route is over it.

    Returns the decision on success so the handler can clear the counters after
    a successful authentication.
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        # An explicit, configured off switch — not a silent one. It exists
        # because a single-process local run against a Redis that is not
        # there would otherwise log an error on every request, and an operator
        # who turns it off has said so in their environment.
        return Decision(allowed=True, rule_name=route, degraded=True)

    decision = await limiter(store).check(
        route, client_ip=request_client_ip(request), identity=identity
    )
    if not decision.allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again later.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )
    return decision


async def clear(
    request: Request,
    route: str,
    *,
    identity: str | None = None,
    store: RedisStore | MemoryStore | None = None,
) -> None:
    if not get_settings().rate_limit_enabled:
        return
    await limiter(store).clear(route, client_ip=request_client_ip(request), identity=identity)
