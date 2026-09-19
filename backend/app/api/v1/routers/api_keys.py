"""API keys for CI/CD (docs/BUILD_SPEC.md §17.4).

Admin and above to mint or revoke, because a key is a standing credential for
the organization. What the key itself can then do is capped well below that:
the highest role any scope maps to is security engineer, so a key cannot
create a target, grant authorization, add a member, or mint another key. A
credential that lives in a CI runner must not be able to authorize a new
target — that grant is the human act this platform is built around.

Rotation is create-then-revoke rather than an in-place secret swap, so a
pipeline can be moved onto the new key before the old one stops working.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.models.api_key import ApiKey, mint_token
from app.models.organization import Membership, Role
from app.schemas.api_key import ApiKeyCreate, ApiKeyCreated, ApiKeyRead

router = APIRouter(prefix="/organizations/{organization_id}/api-keys", tags=["api-keys"])


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    organization_id: uuid.UUID,
    payload: ApiKeyCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> ApiKeyCreated:
    if payload.expires_at is not None and payload.expires_at <= datetime.now(UTC):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="expires_at is in the past; a key that cannot be used is not a key",
        )

    token, key_id, digest = mint_token()
    key = ApiKey(
        organization_id=organization_id,
        name=payload.name,
        key_id=key_id,
        token_digest=digest,
        scopes=[scope.value for scope in payload.scopes],
        created_by_user_id=membership.user_id,
        expires_at=payload.expires_at,
    )
    db.add(key)
    await db.flush()

    await record_event(
        db,
        action="api_key.create",
        resource_type="api_key",
        resource_id=str(key.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        # The id and the scopes, never the token. An audit log that records a
        # credential is a second place the credential leaks from.
        metadata={"key_id": key_id, "scopes": key.scopes, "role": key.role.value},
    )
    await db.commit()

    return ApiKeyCreated(
        id=key.id,
        name=key.name,
        key_id=key.key_id,
        scopes=[str(scope) for scope in key.scopes],
        role=key.role,
        created_at=key.created_at,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        revoked_at=key.revoked_at,
        token=token,
    )


@router.get("", response_model=list[ApiKeyRead])
async def list_api_keys(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> list[ApiKeyRead]:
    rows = (
        await db.execute(
            select(ApiKey)
            .where(ApiKey.organization_id == organization_id)
            .order_by(ApiKey.created_at.desc())
        )
    ).scalars()
    return [_read(key) for key in rows.all()]


@router.post("/{key_id}/revoke", response_model=ApiKeyRead)
async def revoke_api_key(
    organization_id: uuid.UUID,
    key_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> ApiKeyRead:
    key = await _load(organization_id, key_id, db)
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
        await record_event(
            db,
            action="api_key.revoke",
            resource_type="api_key",
            resource_id=str(key.id),
            result="allow",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"key_id": key.key_id},
        )
    await db.commit()
    return _read(key)


def _read(key: ApiKey) -> ApiKeyRead:
    return ApiKeyRead(
        id=key.id,
        name=key.name,
        key_id=key.key_id,
        scopes=[str(scope) for scope in (key.scopes or [])],
        role=key.role,
        created_at=key.created_at,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        revoked_at=key.revoked_at,
    )


async def _load(organization_id: uuid.UUID, key_id: uuid.UUID, db: DbSession) -> ApiKey:
    key = (
        await db.execute(
            select(ApiKey).where(ApiKey.id == key_id, ApiKey.organization_id == organization_id)
        )
    ).scalar_one_or_none()
    if key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="API key not found")
    return key
