"""Session visibility and revocation by name (docs/BUILD_SPEC.md §18,
docs/security-review.md).

Before this, the only things `/auth/logout` and `/auth/logout-all` could
express were "this session" and "every session" — there was no way to see
what was active, or to kill one specific *other* one by name. This adds
`GET /auth/sessions` (list) and `DELETE /auth/sessions/{id}` (revoke one),
backed by a new `user_sessions` table that records what
`app/core/revocation/`'s deny-list never had to: which tokens exist, not
only which are dead.

The deny-list and `User.tokens_valid_after` remain the actual authorization
decision — this table is a record for a human to read, not a second place
that decision is made. `test_revoking_a_session_actually_kills_the_token`
is the one that matters most: it proves `DELETE /auth/sessions/{id}` is not
merely a row update that leaves the token itself still working.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


async def _register(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "S", "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 201, response.text
    return {"bearer": response.json()["access_token"]}


async def _login(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 200, response.text
    return {"bearer": response.json()["access_token"]}


async def test_registering_creates_a_listable_session(
    client: AsyncClient, strong_password: str
) -> None:
    creds = await _register(client, "sess-register@example.test", strong_password)
    headers = {"Authorization": f"Bearer {creds['bearer']}"}

    response = await client.get("/api/v1/auth/sessions", headers=headers)
    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 1
    assert sessions[0]["is_current"] is True


async def test_each_login_adds_a_session_the_list_shows(
    client: AsyncClient, strong_password: str
) -> None:
    """The property that makes this "visibility" rather than a single-row
    gimmick: logging in twice must show two rows, not one overwritten."""
    await _register(client, "sess-multi@example.test", strong_password)
    first = await _login(client, "sess-multi@example.test", strong_password)
    second = await _login(client, "sess-multi@example.test", strong_password)

    response = await client.get(
        "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {second['bearer']}"}
    )
    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 3  # register + two logins

    current_flags = [s["is_current"] for s in sessions]
    assert current_flags.count(True) == 1

    # And the other bearer's own view agrees there are still three, none of
    # them revoked yet — listing does not depend on which token asks.
    other_view = await client.get(
        "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {first['bearer']}"}
    )
    assert len(other_view.json()) == 3


async def test_revoking_a_session_actually_kills_the_token(
    client: AsyncClient, strong_password: str
) -> None:
    """The point of the feature, not just the row update.

    Verified by making `revoke_session` update `revoked_at` without calling
    `revocation.revoke`: the second assertion (the killed token still being
    refused) then fails while the first (it disappearing from the list)
    keeps passing — proving the list alone is not enough evidence that
    anything was actually revoked.
    """
    await _register(client, "sess-kill@example.test", strong_password)
    victim = await _login(client, "sess-kill@example.test", strong_password)
    controller = await _login(client, "sess-kill@example.test", strong_password)

    listing = await client.get(
        "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {controller['bearer']}"}
    )
    target = next(s for s in listing.json() if not s["is_current"])

    revoke = await client.delete(
        f"/api/v1/auth/sessions/{target['id']}",
        headers={"Authorization": f"Bearer {controller['bearer']}"},
    )
    assert revoke.status_code == 204

    after_listing = await client.get(
        "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {controller['bearer']}"}
    )
    assert target["id"] not in [s["id"] for s in after_listing.json()]

    dead = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {victim['bearer']}"}
    )
    assert dead.status_code == 401
    assert "revoked" in dead.text.lower()

    alive = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {controller['bearer']}"}
    )
    assert alive.status_code == 200


async def test_revoking_your_own_current_session_works_too(
    client: AsyncClient, strong_password: str
) -> None:
    """The general endpoint should not have a special case that makes it
    weaker than `/auth/logout` for the one session it's most likely to be
    used on by mistake."""
    await _register(client, "sess-self@example.test", strong_password)
    creds = await _login(client, "sess-self@example.test", strong_password)
    headers = {"Authorization": f"Bearer {creds['bearer']}"}

    listing = await client.get("/api/v1/auth/sessions", headers=headers)
    current = next(s for s in listing.json() if s["is_current"])

    revoke = await client.delete(f"/api/v1/auth/sessions/{current['id']}", headers=headers)
    assert revoke.status_code == 204

    dead = await client.get("/api/v1/auth/me", headers=headers)
    assert dead.status_code == 401


async def test_a_user_cannot_revoke_another_users_session(
    client: AsyncClient, strong_password: str
) -> None:
    """The non-disclosure boundary `require_membership` already uses for a
    different organization's resource, applied here: a caller with no
    legitimate reason to know cannot tell "not yours" from "does not exist"
    for a session id either."""
    await _register(client, "sess-victim@example.test", strong_password)
    victim = await _login(client, "sess-victim@example.test", strong_password)
    attacker_creds = await _register(client, "sess-attacker@example.test", strong_password)

    listing = await client.get(
        "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {victim['bearer']}"}
    )
    target_id = listing.json()[0]["id"]

    response = await client.delete(
        f"/api/v1/auth/sessions/{target_id}",
        headers={"Authorization": f"Bearer {attacker_creds['bearer']}"},
    )
    assert response.status_code == 404

    # And the victim's session is still very much alive.
    still_ok = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {victim['bearer']}"}
    )
    assert still_ok.status_code == 200


async def test_revoking_a_nonexistent_session_id_is_a_404(
    client: AsyncClient, strong_password: str
) -> None:
    creds = await _register(client, "sess-missing@example.test", strong_password)
    response = await client.delete(
        f"/api/v1/auth/sessions/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {creds['bearer']}"},
    )
    assert response.status_code == 404


async def test_logout_all_clears_the_session_list_too(
    client: AsyncClient, strong_password: str
) -> None:
    """`/auth/logout-all` already killed every token by cutoff before this
    feature existed; this checks the *listing* keeps up with that, not just
    the underlying authorization decision `test_revocation.py` already
    covers end to end."""
    await _register(client, "sess-logout-all@example.test", strong_password)
    first = await _login(client, "sess-logout-all@example.test", strong_password)
    await _login(client, "sess-logout-all@example.test", strong_password)

    await client.post(
        "/api/v1/auth/logout-all", headers={"Authorization": f"Bearer {first['bearer']}"}
    )

    fresh = await _login(client, "sess-logout-all@example.test", strong_password)
    listing = await client.get(
        "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {fresh['bearer']}"}
    )
    assert len(listing.json()) == 1
    assert listing.json()[0]["is_current"] is True


@pytest.mark.parametrize("path", ["/api/v1/auth/sessions"])
async def test_sessions_endpoint_requires_authentication(client: AsyncClient, path: str) -> None:
    response = await client.get(path)
    assert response.status_code == 401
