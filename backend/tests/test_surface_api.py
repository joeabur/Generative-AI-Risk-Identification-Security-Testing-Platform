"""Attack-surface API: spec upload, listing, and per-endpoint toggling."""

import json

import pytest
from httpx import AsyncClient

from app.api.v1.routers.surface import sanitize_filename
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Demo AI App", "version": "1.0"},
    "paths": {
        "/api/chat": {"post": {"operationId": "chat", "responses": {"200": {"description": "ok"}}}},
        "/api/orders/{order_id}": {
            "get": {"operationId": "getOrder", "responses": {"200": {"description": "ok"}}}
        },
    },
    "security": [{"bearerAuth": []}],
}


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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _org_with_target(client: AsyncClient, password: str, suffix: str) -> tuple[str, str, str]:
    owner = await _register(client, f"surfaceowner{suffix}@example.test", password)
    header = f"Bearer {owner['access_token']}"
    org = await client.post(
        "/api/v1/organizations",
        json={"name": f"Surface Org {suffix}"},
        headers={"Authorization": header},
    )
    org_id = org.json()["id"]
    target = await client.post(
        f"/api/v1/organizations/{org_id}/targets",
        json={
            "name": "Demo",
            "environment": "staging",
            "kind": "llm_app",
            "base_url": "https://ai.example.test",
        },
        headers={"Authorization": header},
    )
    return org_id, target.json()["id"], header


def _spec_file(document: dict | str = None, name: str = "openapi.json") -> dict:
    body = json.dumps(document if document is not None else SPEC)
    return {"file": (name, body.encode("utf-8"), "application/json")}


async def test_upload_discovers_operations(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "a")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(),
        headers={"Authorization": header},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["endpoints_discovered"] == 2
    assert body["spec"]["title"] == "Demo AI App"
    assert {(e["method"], e["path"]) for e in body["endpoints"]} == {
        ("POST", "/api/chat"),
        ("GET", "/api/orders/{order_id}"),
    }
    assert all(e["requires_auth"] for e in body["endpoints"])
    assert all(e["enabled"] for e in body["endpoints"])


async def test_listing_surface_returns_discovered_endpoints(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "b")
    await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(),
        headers={"Authorization": header},
    )

    response = await client.get(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/surface",
        headers={"Authorization": header},
    )

    assert response.status_code == 200
    assert len(response.json()) == 2


async def test_endpoint_can_be_disabled_and_survives_a_spec_reupload(
    client: AsyncClient, strong_password: str
) -> None:
    """An operator's decision to take an endpoint out of testing must not be
    silently undone by a routine spec refresh."""
    org_id, target_id, header = await _org_with_target(client, strong_password, "c")
    first = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(),
        headers={"Authorization": header},
    )
    chat = next(e for e in first.json()["endpoints"] if e["path"] == "/api/chat")

    disabled = await client.patch(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/surface/{chat['id']}",
        json={"enabled": False},
        headers={"Authorization": header},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    second = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(),
        headers={"Authorization": header},
    )
    reuploaded_chat = next(e for e in second.json()["endpoints"] if e["path"] == "/api/chat")
    reuploaded_order = next(
        e for e in second.json()["endpoints"] if e["path"] == "/api/orders/{order_id}"
    )

    assert reuploaded_chat["enabled"] is False
    assert reuploaded_order["enabled"] is True


async def test_malformed_spec_is_rejected_with_a_readable_message(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "d")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files={"file": ("openapi.json", b"{not valid json", "application/json")},
        headers={"Authorization": header},
    )

    assert response.status_code == 422
    assert "error" in response.json()


async def test_remote_ref_spec_is_rejected_at_the_api_boundary(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "e")
    hostile = {
        "openapi": "3.0.0",
        "info": {"title": "Evil", "version": "1"},
        "paths": {
            "/x": {
                "get": {"parameters": [{"$ref": "https://evil.test/p.yaml#/L"}], "responses": {}}
            }
        },
    }

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(hostile),
        headers={"Authorization": header},
    )

    assert response.status_code == 422
    assert "remote references are not fetched" in response.json()["error"]["message"]


async def test_unsupported_file_type_is_rejected(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "f")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files={"file": ("spec.exe", json.dumps(SPEC).encode("utf-8"), "application/octet-stream")},
        headers={"Authorization": header},
    )

    assert response.status_code == 422
    assert "unsupported file type" in response.json()["error"]["message"]


async def test_yaml_spec_upload_is_accepted(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "g")
    yaml_doc = (
        'openapi: "3.0.0"\n'
        "info:\n  title: YAML App\n  version: '1'\n"
        "paths:\n  /api/search:\n    get:\n      responses:\n        '200':\n"
        "          description: ok\n"
    )

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files={"file": ("openapi.yaml", yaml_doc.encode("utf-8"), "application/yaml")},
        headers={"Authorization": header},
    )

    assert response.status_code == 200
    assert response.json()["endpoints_discovered"] == 1


async def test_viewer_cannot_upload_a_spec(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "h")
    viewer = await _register(client, "surfaceviewer@example.test", strong_password)
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": viewer["user"]["email"], "role": "viewer"},
        headers={"Authorization": header},
    )

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(),
        headers=_auth(viewer["access_token"]),
    )

    assert response.status_code == 403


async def test_viewer_cannot_toggle_an_endpoint(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "i")
    uploaded = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(),
        headers={"Authorization": header},
    )
    endpoint_id = uploaded.json()["endpoints"][0]["id"]

    viewer = await _register(client, "surfaceviewer2@example.test", strong_password)
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": viewer["user"]["email"], "role": "viewer"},
        headers={"Authorization": header},
    )

    response = await client.patch(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/surface/{endpoint_id}",
        json={"enabled": False},
        headers=_auth(viewer["access_token"]),
    )

    assert response.status_code == 403


async def test_surface_is_not_visible_from_another_organization(
    client: AsyncClient, strong_password: str
) -> None:
    org_a, target_a, header_a = await _org_with_target(client, strong_password, "j1")
    org_b, _, header_b = await _org_with_target(client, strong_password, "j2")
    await client.put(
        f"/api/v1/organizations/{org_a}/targets/{target_a}/openapi",
        files=_spec_file(),
        headers={"Authorization": header_a},
    )

    response = await client.get(
        f"/api/v1/organizations/{org_b}/targets/{target_a}/surface",
        headers={"Authorization": header_b},
    )

    assert response.status_code == 404


async def test_spec_metadata_is_retrievable(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "k")
    await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files=_spec_file(),
        headers={"Authorization": header},
    )

    response = await client.get(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        headers={"Authorization": header},
    )

    assert response.status_code == 200
    assert response.json()["openapi_version"] == "3.0.3"


async def test_missing_spec_returns_404(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "l")

    response = await client.get(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        headers={"Authorization": header},
    )

    assert response.status_code == 404


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\cfg", "cfg"),
        ("/absolute/path/openapi.yaml", "openapi.yaml"),
        ("..", "uploaded-spec"),
        ("", "uploaded-spec"),
        (None, "uploaded-spec"),
    ],
)
def test_filename_sanitization_strips_traversal(raw: str | None, expected: str) -> None:
    assert sanitize_filename(raw) == expected
