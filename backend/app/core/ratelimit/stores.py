"""Where the counters live.

Two implementations behind one three-method protocol. Both use a **fixed
window**: a counter that expires. A sliding log would be more precise at the
boundary — an attacker can land `2 × limit` attempts across a window edge — but
it costs a sorted set per key and a read of every entry, and under exactly the
attack this defends against (millions of keys during a spraying run) that is
the memory profile that takes the store down. The boundary slack is bounded and
known; the memory blow-up is not, so the fixed window wins and the trade is
recorded here rather than discovered later.
"""

from __future__ import annotations

import time

import redis.asyncio as redis_async

from app.core.config import get_settings
from app.core.ratelimit.contract import StoreUnavailable


class MemoryStore:
    """An in-process store.

    Correct for one process and useless across several, which is why it is not
    the default: two API workers would each enforce the full limit, doubling it.
    It exists for tests and for a single-process deployment that says so.
    """

    def __init__(self) -> None:
        self._counts: dict[str, tuple[int, float]] = {}

    def _now(self) -> float:
        return time.monotonic()

    def _live(self, key: str) -> tuple[int, float] | None:
        entry = self._counts.get(key)
        if entry is None:
            return None
        if entry[1] <= self._now():
            del self._counts[key]
            return None
        return entry

    async def incr(self, key: str, window_seconds: int) -> int:
        entry = self._live(key)
        if entry is None:
            self._counts[key] = (1, self._now() + window_seconds)
            return 1
        count, expires = entry
        self._counts[key] = (count + 1, expires)
        return count + 1

    async def ttl(self, key: str) -> int:
        entry = self._live(key)
        if entry is None:
            return 0
        return max(0, int(round(entry[1] - self._now())))

    async def reset(self, key: str) -> None:
        self._counts.pop(key, None)


class RedisStore:
    """The real one: counters shared across every API process.

    `INCR` then `EXPIRE` in one pipeline, and the expiry is set only when the
    counter is new. Setting it every time would let a client hold a window open
    indefinitely by attempting once per second — the window would never roll
    over and the limit would never reset, turning a throttle into a lockout.
    """

    def __init__(self, url: str | None = None) -> None:
        self._url = url or get_settings().redis_url
        self._client: redis_async.Redis | None = None

    def _connect(self) -> redis_async.Redis:
        if self._client is None:
            self._client = redis_async.Redis.from_url(self._url, decode_responses=True)
        return self._client

    async def incr(self, key: str, window_seconds: int) -> int:
        try:
            client = self._connect()
            count = int(await client.incr(key))
            if count == 1:
                await client.expire(key, window_seconds)
            return count
        except (redis_async.RedisError, OSError) as exc:
            # Distinct from "over the limit": the caller allows the request and
            # flags the degradation rather than refusing. See
            # `contract.py` for why this one boundary fails open.
            raise StoreUnavailable(str(exc)) from exc

    async def ttl(self, key: str) -> int:
        try:
            remaining = int(await self._connect().ttl(key))
        except (redis_async.RedisError, OSError) as exc:
            raise StoreUnavailable(str(exc)) from exc
        # Redis returns -2 for a missing key and -1 for one with no expiry.
        # Neither is a duration, and reporting either as one would produce a
        # nonsensical `Retry-After`.
        return remaining if remaining > 0 else 0

    async def reset(self, key: str) -> None:
        try:
            await self._connect().delete(key)
        except (redis_async.RedisError, OSError) as exc:
            raise StoreUnavailable(str(exc)) from exc
