"""Attack-surface discovery endpoints: upload an OpenAPI document, review
what it exposes, and enable/disable individual endpoints
(docs/BUILD_SPEC.md §18.5, §26 Phase 3).
"""

import os
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.v1.routers.targets import load_target
from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.discovery import openapi
from app.models.api_spec import ApiSpec
from app.models.organization import Membership, Role
from app.models.surface_endpoint import SurfaceEndpoint, SurfaceSource
from app.models.synthetic_account import SyntheticAccount
from app.models.target import Target
from app.schemas.surface import (
    ApiSpecRead,
    SurfaceEndpointRead,
    SurfaceEndpointUpdate,
    SurfaceImportResult,
)
from app.schemas.synthetic_account import SyntheticAccountRead, SyntheticAccountUpsert

router = APIRouter(prefix="/organizations/{organization_id}/targets", tags=["surface"])

ALLOWED_SPEC_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})


def sanitize_filename(raw: str | None) -> str:
    """Reduce an uploaded filename to a safe, storable label.

    The result is **metadata only** — `ApiSpec` keeps the document in a
    database column and this value never becomes part of a filesystem path,
    so this is defence in depth rather than the primary control against
    traversal (see the note on `app/models/api_spec.py`).
    """
    if not raw:
        return "uploaded-spec"
    name = os.path.basename(raw.replace("\\", "/")).strip()
    name = name.replace("\x00", "")
    if name in {"", ".", ".."}:
        return "uploaded-spec"
    return name[:255]


@router.put("/{target_id}/openapi", response_model=SurfaceImportResult)
async def import_openapi_spec(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    request: Request,
    db: DbSession,
    file: UploadFile = File(...),  # noqa: B008
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> SurfaceImportResult:
    """Parse an uploaded OpenAPI 3.x document into a reviewable surface.

    Re-uploading a spec preserves the `enabled` flag of any endpoint that
    still exists by method+path: an operator who deliberately took an
    endpoint out of scope should not have that decision silently undone by a
    routine spec refresh.
    """
    target = await load_target(organization_id, target_id, db)

    filename = sanitize_filename(file.filename)
    extension = os.path.splitext(filename)[1].lower()
    if extension not in ALLOWED_SPEC_EXTENSIONS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"unsupported file type {extension or '(none)'}; expected .json, .yaml or .yml",
        )

    raw = await file.read(openapi.MAX_DOCUMENT_BYTES + 1)
    if len(raw) > openapi.MAX_DOCUMENT_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"spec exceeds the {openapi.MAX_DOCUMENT_BYTES} byte limit",
        )

    try:
        discovered = openapi.parse(raw)
    except openapi.OpenApiParseError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    existing = await db.execute(
        select(SurfaceEndpoint).where(SurfaceEndpoint.target_id == target.id)
    )
    existing_rows = list(existing.scalars().all())
    previously_disabled = {(row.method, row.path) for row in existing_rows if not row.enabled}

    for row in existing_rows:
        await db.delete(row)
    if target.api_spec is not None:
        await db.delete(target.api_spec)
    await db.flush()

    spec = ApiSpec(
        target_id=target.id,
        original_filename=filename,
        openapi_version=discovered.openapi_version,
        title=discovered.title,
        api_version=discovered.version,
        raw_document=raw.decode("utf-8"),
        uploaded_by_user_id=membership.user_id,
    )
    db.add(spec)
    await db.flush()

    endpoints: list[SurfaceEndpoint] = []
    for operation in discovered.operations:
        endpoint = SurfaceEndpoint(
            target_id=target.id,
            api_spec_id=spec.id,
            method=operation.method,
            path=operation.path,
            operation_id=operation.operation_id,
            summary=operation.summary,
            parameters=[
                {
                    "name": parameter.name,
                    "in": parameter.location,
                    "required": parameter.required,
                    "type": parameter.schema_type,
                }
                for parameter in operation.parameters
            ],
            request_body_content_types=list(operation.request_body_content_types),
            body_fields=[
                {
                    "name": field.name,
                    "type": field.schema_type,
                    "required": field.required,
                    "read_only": field.read_only,
                    "enum": list(field.enum_values),
                    "minimum": field.minimum,
                    "maximum": field.maximum,
                    "max_length": field.max_length,
                }
                for field in operation.body_fields
            ],
            body_required=operation.body_required,
            security_schemes=list(operation.security_schemes),
            requires_auth=operation.requires_auth,
            enabled=(operation.method, operation.path) not in previously_disabled,
            source=SurfaceSource.OPENAPI,
        )
        db.add(endpoint)
        endpoints.append(endpoint)
    await db.flush()

    await record_event(
        db,
        action="target.surface.import",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"filename": filename, "operations": len(endpoints)},
    )
    await db.commit()

    return SurfaceImportResult(
        spec=ApiSpecRead.model_validate(spec),
        endpoints_discovered=len(endpoints),
        endpoints=[SurfaceEndpointRead.model_validate(endpoint) for endpoint in endpoints],
    )


@router.get("/{target_id}/surface", response_model=list[SurfaceEndpointRead])
async def list_surface(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[SurfaceEndpointRead]:
    await load_target(organization_id, target_id, db)
    result = await db.execute(
        select(SurfaceEndpoint)
        .where(SurfaceEndpoint.target_id == target_id)
        .order_by(SurfaceEndpoint.path, SurfaceEndpoint.method)
    )
    return [SurfaceEndpointRead.model_validate(row) for row in result.scalars().all()]


@router.get("/{target_id}/openapi", response_model=ApiSpecRead)
async def get_api_spec(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> ApiSpecRead:
    result = await db.execute(
        select(Target)
        .where(Target.id == target_id, Target.organization_id == organization_id)
        .options(selectinload(Target.api_spec))
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Target not found")
    if target.api_spec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No API spec uploaded")
    return ApiSpecRead.model_validate(target.api_spec)


@router.patch("/{target_id}/surface/{endpoint_id}", response_model=SurfaceEndpointRead)
async def update_surface_endpoint(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    payload: SurfaceEndpointUpdate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> SurfaceEndpointRead:
    """Enable or disable one endpoint for testing.

    This narrows what a run will touch; it can never widen it. Whatever is
    stored here, every request is still checked against the Rules of
    Engagement by the scope engine (§6).
    """
    await load_target(organization_id, target_id, db)

    result = await db.execute(
        select(SurfaceEndpoint).where(
            SurfaceEndpoint.id == endpoint_id, SurfaceEndpoint.target_id == target_id
        )
    )
    endpoint = result.scalar_one_or_none()
    if endpoint is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    endpoint.enabled = payload.enabled
    await db.flush()

    await record_event(
        db,
        action="target.surface.endpoint_updated",
        resource_type="surface_endpoint",
        resource_id=str(endpoint.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"enabled": payload.enabled, "method": endpoint.method, "path": endpoint.path},
    )
    await db.commit()

    return SurfaceEndpointRead.model_validate(endpoint)


@router.put("/{target_id}/accounts/{label}", response_model=SyntheticAccountRead)
async def upsert_synthetic_account(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    label: str,
    payload: SyntheticAccountUpsert,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> SyntheticAccountRead:
    """Declare an authorized synthetic test account.

    Admin-only, alongside the authorization grant, because declaring a test
    account is asserting that the operator is entitled to use it. The
    platform stores the *name* of an environment variable the worker will
    read; the credential itself never reaches this process, the database, or
    a report (docs/BUILD_SPEC.md §2, §10).
    """
    target = await load_target(organization_id, target_id, db)
    if payload.label != label:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="label in the path and the body must match",
        )

    result = await db.execute(
        select(SyntheticAccount).where(
            SyntheticAccount.target_id == target.id, SyntheticAccount.label == label
        )
    )
    account = result.scalar_one_or_none()
    if account is None:
        account = SyntheticAccount(target_id=target.id, label=label)
        db.add(account)

    account.description = payload.description
    account.credential_env_var = payload.credential_env_var
    account.header_name = payload.header_name
    account.value_template = payload.value_template
    account.owned_object_ids = list(payload.owned_object_ids)
    account.is_privileged = payload.is_privileged
    await db.flush()

    await record_event(
        db,
        action="target.account.upsert",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        # The variable name is metadata, not a secret; its value is never
        # read by this process at all.
        metadata={"label": label, "credential_env_var": payload.credential_env_var},
    )
    await db.commit()

    return SyntheticAccountRead.model_validate(account)


@router.get("/{target_id}/accounts", response_model=list[SyntheticAccountRead])
async def list_synthetic_accounts(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[SyntheticAccountRead]:
    target = await load_target(organization_id, target_id, db)
    result = await db.execute(
        select(SyntheticAccount)
        .where(SyntheticAccount.target_id == target.id)
        .order_by(SyntheticAccount.label)
    )
    return [SyntheticAccountRead.model_validate(row) for row in result.scalars().all()]


@router.delete("/{target_id}/accounts/{label}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_synthetic_account(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    label: str,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> None:
    target = await load_target(organization_id, target_id, db)
    result = await db.execute(
        select(SyntheticAccount).where(
            SyntheticAccount.target_id == target.id, SyntheticAccount.label == label
        )
    )
    account = result.scalar_one_or_none()
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Account not found")

    await db.delete(account)
    await record_event(
        db,
        action="target.account.delete",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"label": label},
    )
    await db.commit()
