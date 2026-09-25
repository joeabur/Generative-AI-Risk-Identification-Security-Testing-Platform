from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME

pytestmark = pytest.mark.asyncio


async def _register(client: AsyncClient, email: str, password: str) -> dict:
    _response_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0].title(), "password": password},
        headers={HEADER_NAME: _response_anon_token},
    )
    assert response.status_code == 201
    return response.json()


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _make_org_with_owner(
    client: AsyncClient, strong_password: str, suffix: str
) -> tuple[dict, str, dict]:
    owner = await _register(client, f"owner{suffix}@example.test", strong_password)
    headers = _auth_headers(owner["access_token"])
    create = await client.post(
        "/api/v1/organizations", json={"name": f"Org {suffix}"}, headers=headers
    )
    assert create.status_code == 201
    return owner, headers["Authorization"], create.json()


def _valid_roe_payload(**overrides: object) -> dict:
    payload = {
        "allowed_domains": ["ai.example.test", "*.ai.example.test"],
        "excluded_domains": [],
        "allowed_ip_ranges": [],
        "allowed_paths": ["/api/*"],
        "excluded_paths": ["/api/admin/*"],
        "allowed_methods": ["GET", "POST"],
        "forbidden_headers": [],
        "budgets": {
            "max_requests": 500,
            "max_concurrency": 3,
            "requests_per_second": 2.0,
            "max_tokens_sent": 100000,
            "max_tokens_received": 200000,
            "max_estimated_cost_usd": 5.0,
            "max_wall_clock_minutes": 30,
        },
        "safe_mode": True,
    }
    payload.update(overrides)
    return payload


def _valid_authorization_payload() -> dict:
    now = datetime.now(UTC)
    return {
        "authorized_by_name": "Alice Owner",
        "authorized_by_role": "CISO",
        "authorized_by_email": "ciso@example.test",
        "reference": "TICKET-1234",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=6)).isoformat(),
    }


async def test_admin_can_create_target(client: AsyncClient, strong_password: str) -> None:
    _, auth_header, org = await _make_org_with_owner(client, strong_password, "a")
    response = await client.post(
        f"/api/v1/organizations/{org['id']}/targets",
        json={
            "name": "Demo AI App",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers={"Authorization": auth_header},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Demo AI App"
    assert body["has_authorization"] is False
    assert body["has_rules_of_engagement"] is False


async def test_viewer_cannot_create_target(client: AsyncClient, strong_password: str) -> None:
    owner, owner_auth, org = await _make_org_with_owner(client, strong_password, "b")
    viewer = await _register(client, "viewertarget@example.test", strong_password)
    await client.post(
        f"/api/v1/organizations/{org['id']}/members",
        json={"email": viewer["user"]["email"], "role": "viewer"},
        headers={"Authorization": owner_auth},
    )

    response = await client.post(
        f"/api/v1/organizations/{org['id']}/targets",
        json={
            "name": "Demo AI App",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers=_auth_headers(viewer["access_token"]),
    )
    assert response.status_code == 403


async def test_target_not_visible_from_another_organization(
    client: AsyncClient, strong_password: str
) -> None:
    _, auth_header_a, org_a = await _make_org_with_owner(client, strong_password, "c1")
    _, auth_header_b, org_b = await _make_org_with_owner(client, strong_password, "c2")

    create = await client.post(
        f"/api/v1/organizations/{org_a['id']}/targets",
        json={
            "name": "Org A Target",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers={"Authorization": auth_header_a},
    )
    target_id = create.json()["id"]

    # Right target id, wrong organization in the path -> not found.
    response = await client.get(
        f"/api/v1/organizations/{org_b['id']}/targets/{target_id}",
        headers={"Authorization": auth_header_b},
    )
    assert response.status_code == 404


async def test_set_rules_of_engagement_validates_and_persists(
    client: AsyncClient, strong_password: str
) -> None:
    _, auth_header, org = await _make_org_with_owner(client, strong_password, "d")
    create = await client.post(
        f"/api/v1/organizations/{org['id']}/targets",
        json={
            "name": "Demo",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers={"Authorization": auth_header},
    )
    target_id = create.json()["id"]

    bad = await client.put(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/rules-of-engagement",
        json={"allowed_domains": "not-a-list"},
        headers={"Authorization": auth_header},
    )
    assert bad.status_code == 422

    good = await client.put(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/rules-of-engagement",
        json=_valid_roe_payload(),
        headers={"Authorization": auth_header},
    )
    assert good.status_code == 200
    assert good.json()["allowed_domains"] == ["ai.example.test", "*.ai.example.test"]

    fetched = await client.get(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}",
        headers={"Authorization": auth_header},
    )
    assert fetched.json()["has_rules_of_engagement"] is True


async def test_only_admin_can_grant_authorization(
    client: AsyncClient, strong_password: str
) -> None:
    owner, owner_auth, org = await _make_org_with_owner(client, strong_password, "e")
    engineer = await _register(client, "secengtarget@example.test", strong_password)
    await client.post(
        f"/api/v1/organizations/{org['id']}/members",
        json={"email": engineer["user"]["email"], "role": "security_engineer"},
        headers={"Authorization": owner_auth},
    )
    create = await client.post(
        f"/api/v1/organizations/{org['id']}/targets",
        json={
            "name": "Demo",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers={"Authorization": owner_auth},
    )
    target_id = create.json()["id"]

    forbidden = await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/authorization",
        json=_valid_authorization_payload(),
        headers=_auth_headers(engineer["access_token"]),
    )
    assert forbidden.status_code == 403

    allowed = await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/authorization",
        json=_valid_authorization_payload(),
        headers={"Authorization": owner_auth},
    )
    assert allowed.status_code == 201


async def test_scope_explain_without_authorization_or_roe(
    client: AsyncClient, strong_password: str
) -> None:
    _, auth_header, org = await _make_org_with_owner(client, strong_password, "f")
    create = await client.post(
        f"/api/v1/organizations/{org['id']}/targets",
        json={
            "name": "Demo",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers={"Authorization": auth_header},
    )
    target_id = create.json()["id"]

    response = await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/scope/explain",
        json={"method": "GET", "url": "https://ai.example.test/api/chat"},
        headers={"Authorization": auth_header},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert body["rule"] == "authorization_required"


async def test_scope_explain_allowed_and_blocked_after_configuration(
    client: AsyncClient, strong_password: str
) -> None:
    _, auth_header, org = await _make_org_with_owner(client, strong_password, "g")
    create = await client.post(
        f"/api/v1/organizations/{org['id']}/targets",
        json={
            "name": "Demo",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers={"Authorization": auth_header},
    )
    target_id = create.json()["id"]

    await client.put(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/rules-of-engagement",
        json=_valid_roe_payload(),
        headers={"Authorization": auth_header},
    )
    await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/authorization",
        json=_valid_authorization_payload(),
        headers={"Authorization": auth_header},
    )

    in_scope = await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/scope/explain",
        json={"method": "GET", "url": "https://ai.example.test/api/chat"},
        headers={"Authorization": auth_header},
    )
    assert in_scope.json() == {
        "allowed": True,
        "rule": "allow",
        "reason": "request would be in scope",
    }

    excluded_path = await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/scope/explain",
        json={"method": "GET", "url": "https://ai.example.test/api/admin/users"},
        headers={"Authorization": auth_header},
    )
    assert excluded_path.json()["allowed"] is False
    assert excluded_path.json()["rule"] == "excluded_path"

    off_scope_domain = await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/scope/explain",
        json={"method": "GET", "url": "https://evil.test/api/chat"},
        headers={"Authorization": auth_header},
    )
    assert off_scope_domain.json()["allowed"] is False
    assert off_scope_domain.json()["rule"] == "domain_not_allowlisted"

    wrong_method = await client.post(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/scope/explain",
        json={"method": "DELETE", "url": "https://ai.example.test/api/chat"},
        headers={"Authorization": auth_header},
    )
    assert wrong_method.json()["allowed"] is False
    assert wrong_method.json()["rule"] == "method_not_allowed"

    # scope/explain must not consume the request budget it previewed against.
    roe_after = await client.get(
        f"/api/v1/organizations/{org['id']}/targets/{target_id}/rules-of-engagement",
        headers={"Authorization": auth_header},
    )
    assert roe_after.status_code == 200
