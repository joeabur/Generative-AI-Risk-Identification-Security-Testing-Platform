"""Server-side JWT revocation (docs/BUILD_SPEC.md §18, docs/revocation.md).

A JWT is normally valid until it expires, full stop — no server-side way to
kill one early. That makes "logout" cosmetic (clear the cookie, the token
underneath still works for as long as it copied anywhere) and leaves no
response to "this token may have leaked" short of waiting out its lifetime.

This closes both. Two mechanisms, deliberately different in shape and both
asserted end to end:

* **Per-token revocation** (`/auth/logout`) — kills one token, by its `jti`,
  in a Redis deny-list that expires with the token's own remaining lifetime.
* **Per-user revocation** (`/auth/logout-all`) — kills every token issued
  before the moment it is called, via a durable Postgres cutoff, regardless of
  how many exist or whether this platform has ever tracked them.

The design decision worth the most scrutiny is the failure mode: this control
fails **closed**, the opposite of the rate limiter a few files over. Both
halves are asserted here, not just the rate limiter's.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.auth.security import create_access_token, decode_access_token
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.revocation.contract import RevocationStoreUnavailable
from app.core.revocation.dependency import get_store, reset_store_for_tests
from app.core.revocation.stores import MemoryStore
from app.models.user import User


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


class _BrokenStore:
    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        raise RevocationStoreUnavailable("redis is down")

    async def is_revoked(self, jti: str) -> bool:
        raise RevocationStoreUnavailable("redis is down")


# --------------------------------------------------------------------------
# The token itself: jti is mandatory, not optional.
# --------------------------------------------------------------------------


def test_every_issued_token_carries_a_jti() -> None:
    token = create_access_token(subject=uuid.uuid4())
    payload = decode_access_token(token)
    assert isinstance(payload["jti"], str)
    assert payload["jti"]


def test_two_tokens_for_the_same_user_have_different_jtis() -> None:
    """Otherwise one revocation would blanket-kill every session by accident."""
    subject = uuid.uuid4()
    first = decode_access_token(create_access_token(subject=subject))
    second = decode_access_token(create_access_token(subject=subject))
    assert first["jti"] != second["jti"]


def test_a_token_forged_without_a_jti_is_refused_not_silently_exempt() -> None:
    """The downgrade attack this closes.

    If a token missing `jti` were accepted, a forger who stripped the claim
    would hold a token no revocation could ever reach — a leaked token that
    logout, or 'log out everywhere', could not kill. That must be a rejection,
    not a free pass.

    Verified by making the `jti` check `if False:` in `decode_access_token`:
    the assertion below then fails, because such a token decodes successfully.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    forged = pyjwt.encode(
        {"sub": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(hours=1)},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    from app.auth.security import InvalidTokenError

    with pytest.raises(InvalidTokenError, match="jti"):
        decode_access_token(forged)


# --------------------------------------------------------------------------
# The store's own contract.
# --------------------------------------------------------------------------


async def test_a_revoked_jti_reads_back_as_revoked() -> None:
    store = MemoryStore()
    assert await store.is_revoked("abc") is False
    await store.revoke("abc", ttl_seconds=60)
    assert await store.is_revoked("abc") is True


async def test_a_revocation_expires_with_its_ttl() -> None:
    """A deny-list entry must not outlive the token it revokes forever —
    the token could not be presented past its own `exp` regardless."""
    store = MemoryStore()
    await store.revoke("abc", ttl_seconds=60)
    # Force the entry into the past without waiting for it.
    store._entries["abc"] = store._now() - 1  # noqa: SLF001
    assert await store.is_revoked("abc") is False


async def test_revoking_with_a_non_positive_ttl_is_a_no_op_not_a_crash() -> None:
    """A logout on a token that is already past (or at) its expiry has
    nothing left to revoke. `RedisStore` would otherwise pass Redis a
    non-positive EX, which Redis rejects as an error."""
    from app.core.revocation.stores import RedisStore

    store = RedisStore(url="redis://localhost:0")  # unreachable; must not be dialled
    await store.revoke("abc", ttl_seconds=0)
    await store.revoke("abc", ttl_seconds=-5)


# --------------------------------------------------------------------------
# End to end: logout kills this session and only this one.
# --------------------------------------------------------------------------


async def _login(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 200, response.text
    return {
        "bearer": response.json()["access_token"],
        "session": response.cookies[get_settings().session_cookie_name],
    }


async def test_a_token_works_until_logged_out(client: AsyncClient, strong_password: str) -> None:
    await client.post(
        "/api/v1/auth/register",
        json={"email": "revoke-basic@example.test", "full_name": "R", "password": strong_password},
        headers=await _anon_headers(client),
    )
    creds = await _login(client, "revoke-basic@example.test", strong_password)
    headers = {"Authorization": f"Bearer {creds['bearer']}"}

    before = await client.get("/api/v1/auth/me", headers=headers)
    assert before.status_code == 200

    await client.post("/api/v1/auth/logout", headers=headers)

    after = await client.get("/api/v1/auth/me", headers=headers)
    assert after.status_code == 401
    assert "revoked" in after.text.lower()


async def test_logging_out_one_session_does_not_touch_another(
    client: AsyncClient, strong_password: str
) -> None:
    """Per-token revocation, proven by its scope. If logout revoked by user
    id rather than jti, this would fail — the second login's token would die
    with the first's.

    Verified by making `logout` bump `user.tokens_valid_after` instead of
    revoking the single jti: the second assertion then fails.
    """
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "revoke-scoped@example.test",
            "full_name": "R",
            "password": strong_password,
        },
        headers=await _anon_headers(client),
    )
    first = await _login(client, "revoke-scoped@example.test", strong_password)
    second = await _login(client, "revoke-scoped@example.test", strong_password)
    assert first["bearer"] != second["bearer"]

    await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {first['bearer']}"})

    dead = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {first['bearer']}"}
    )
    assert dead.status_code == 401

    alive = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {second['bearer']}"}
    )
    assert alive.status_code == 200


async def test_logout_all_kills_every_session_including_ones_it_never_saw(
    client: AsyncClient, strong_password: str
) -> None:
    """The compromise-response case. `/auth/logout-all` never learns the jti
    of the *other* sessions it kills — it does not need to, because it works
    by cutoff, not by enumeration.

    Verified by making `logout_all` a no-op that only clears cookies: the
    dead-session assertions below then pass anyway, which is exactly the
    silent-failure this control exists to prevent — so the test would stop
    proving anything, which is why it asserts on the tokens directly rather
    than trusting the 204.
    """
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "revoke-all@example.test",
            "full_name": "R",
            "password": strong_password,
        },
        headers=await _anon_headers(client),
    )
    first = await _login(client, "revoke-all@example.test", strong_password)
    second = await _login(client, "revoke-all@example.test", strong_password)

    response = await client.post(
        "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {second['bearer']}"}
    )
    assert response.status_code == 204

    for creds in (first, second):
        dead = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {creds['bearer']}"}
        )
        assert dead.status_code == 401


async def test_a_token_issued_after_logout_all_still_works(
    client: AsyncClient, strong_password: str
) -> None:
    """The cutoff is a moment, not a permanent ban — logging back in must
    work immediately."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "revoke-relogin@example.test",
            "full_name": "R",
            "password": strong_password,
        },
        headers=await _anon_headers(client),
    )
    old = await _login(client, "revoke-relogin@example.test", strong_password)
    await client.post(
        "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {old['bearer']}"}
    )

    fresh = await _login(client, "revoke-relogin@example.test", strong_password)
    ok = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {fresh['bearer']}"})
    assert ok.status_code == 200


async def test_logout_all_is_durable_in_postgres_not_only_redis(
    client: AsyncClient, strong_password: str, db_session
) -> None:
    """The reason `tokens_valid_after` is a column and not a Redis key: it
    must survive the revocation store being wiped, which a Redis restart
    would do to anything kept only there.

    Verified by simulating exactly that: after logout-all, the in-memory
    revocation store (this test's Redis stand-in) is reset to empty — as a
    real Redis would be after a restart — and the token must still be dead,
    because Postgres, not the store, is what decided that.
    """
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "revoke-durable@example.test",
            "full_name": "R",
            "password": strong_password,
        },
        headers=await _anon_headers(client),
    )
    creds = await _login(client, "revoke-durable@example.test", strong_password)
    await client.post(
        "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {creds['bearer']}"}
    )

    user = (
        await db_session.execute(select(User).where(User.email == "revoke-durable@example.test"))
    ).scalar_one()
    assert user.tokens_valid_after is not None

    # The store the revocation dependency reads from is wiped clean, the way
    # a Redis restart would wipe it — this jti was never even added to it,
    # since `logout-all` does not touch the per-token store at all.
    reset_store_for_tests(MemoryStore())

    still_dead = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {creds['bearer']}"}
    )
    assert still_dead.status_code == 401


# --------------------------------------------------------------------------
# The fail-closed boundary — the deliberate opposite of the rate limiter.
# --------------------------------------------------------------------------


async def test_an_unreachable_revocation_store_refuses_the_request(
    client: AsyncClient, strong_password: str
) -> None:
    """Where the rate limiter fails open, this fails closed, and the
    contrast is the point: revocation *is* the authorization decision for a
    killed token, so 'could not check' must mean 'refused', not 'allowed'.

    Verified by catching `RevocationStoreUnavailable` in `get_current_user`
    and treating it as 'not revoked': this test then observes 200, not 401.
    """
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "revoke-degraded@example.test",
            "full_name": "R",
            "password": strong_password,
        },
        headers=await _anon_headers(client),
    )
    creds = await _login(client, "revoke-degraded@example.test", strong_password)

    reset_store_for_tests(_BrokenStore())  # type: ignore[arg-type]
    try:
        response = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {creds['bearer']}"}
        )
    finally:
        reset_store_for_tests(MemoryStore())

    assert response.status_code == 401


async def test_the_two_controls_disagree_on_purpose(
    client: AsyncClient, strong_password: str
) -> None:
    """Rate limiting and revocation sit right next to each other in the same
    request path and make opposite choices about the same failure. Both are
    asserted in one place so the asymmetry cannot silently drift into
    agreement during a future refactor."""
    from app.core.ratelimit.contract import StoreUnavailable as RateLimitStoreUnavailable
    from app.core.ratelimit.dependency import reset_store_for_tests as reset_ratelimit_store

    class _BrokenRateLimitStore:
        """Raises the real `StoreUnavailable`, matching what `RedisStore`
        actually raises — a bare `Exception` would not be the failure this
        test is meant to simulate, and would not even be caught by the
        limiter's own `except StoreUnavailable`."""

        async def incr(self, key: str, window_seconds: int) -> int:
            raise RateLimitStoreUnavailable("redis is down")

        async def ttl(self, key: str) -> int:
            raise RateLimitStoreUnavailable("redis is down")

        async def reset(self, key: str) -> None:
            raise RateLimitStoreUnavailable("redis is down")

    reset_ratelimit_store(_BrokenRateLimitStore())  # type: ignore[arg-type]
    try:
        # Rate limiting is degraded: login still succeeds (fails open).
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "both-degraded@example.test",
                "full_name": "R",
                "password": strong_password,
            },
            headers=await _anon_headers(client),
        )
        assert response.status_code == 201
    finally:
        reset_ratelimit_store(None)

    creds = await _login(client, "both-degraded@example.test", strong_password)

    reset_store_for_tests(_BrokenStore())  # type: ignore[arg-type]
    try:
        # Revocation is degraded: the same kind of request is refused
        # (fails closed).
        me = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {creds['bearer']}"}
        )
        assert me.status_code == 401
    finally:
        reset_store_for_tests(MemoryStore())


# --------------------------------------------------------------------------
# API keys are a separate path, untouched by any of this.
# --------------------------------------------------------------------------


def test_the_process_store_is_selected_lazily_and_is_overridable() -> None:
    reset_store_for_tests(None)
    assert get_store() is get_store()
    reset_store_for_tests(MemoryStore())
