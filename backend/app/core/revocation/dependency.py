"""The process-wide revocation store, and the two operations callers use.

Mirrors `app/core/ratelimit/dependency.py`'s shape — one module-level store,
overridable in tests — but there is no `enabled` flag. Rate limiting and CSRF
are both mitigations an operator could reasonably run without in a pinch;
turning revocation off would make "logout" cosmetic, clearing a cookie while
the token underneath kept working. That is not a degraded mode worth naming
in a settings file — it is just broken.
"""

from __future__ import annotations

from app.core.revocation.stores import MemoryStore, RedisStore

_store: RedisStore | MemoryStore | None = None


def get_store() -> RedisStore | MemoryStore:
    global _store
    if _store is None:
        _store = RedisStore()
    return _store


def reset_store_for_tests(store: RedisStore | MemoryStore | None = None) -> None:
    global _store
    _store = store


async def revoke(jti: str, ttl_seconds: int) -> None:
    await get_store().revoke(jti, ttl_seconds)


async def is_revoked(jti: str) -> bool:
    """Raises `RevocationStoreUnavailable` on a store failure.

    Deliberately not caught here: `contract.py` requires the caller —
    `get_current_user` — to fail closed on that exception, and catching it in
    this thin wrapper would be the one place that guarantee could quietly be
    lost.
    """
    return await get_store().is_revoked(jti)
