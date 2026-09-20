"""Code-host connections and publishing to a pull request (§27).

Admin to create, change or delete a connection, because a code-host connection
is a standing credential reference for the organization's source. Publishing is
**security engineer**, not admin: posting a check run is part of running an
assessment, and requiring an admin for it would push teams towards sharing an
admin credential with CI — which is the outcome the API-key role cap exists to
prevent.

Reading connections and the post history is analyst, so the people triaging
findings can see what was said on a pull request without being able to re-point
the connection.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.vcs.contract import RepoRef, VcsError
from app.core.vcs.service import destination_for, findings_for_run, publish
from app.models.assessment_run import AssessmentRun
from app.models.organization import Membership, Role
from app.models.vcs import PullRequestPost, VcsConnection
from app.schemas.vcs import (
    PublishRequest,
    PullRequestPostRead,
    VcsConnectionCreate,
    VcsConnectionRead,
    VcsConnectionUpdate,
)

router = APIRouter(prefix="/organizations/{organization_id}/vcs-connections", tags=["vcs"])

#: Hoisted so the dependency fits on one line below and keeps its
#: `.minimum_role` tag, which the authorization matrix reads.
_PUBLISHER = require_membership(Role.SECURITY_ENGINEER)


async def _load(
    db: DbSession, organization_id: uuid.UUID, connection_id: uuid.UUID
) -> VcsConnection:
    result = await db.execute(
        select(VcsConnection).where(
            VcsConnection.id == connection_id,
            VcsConnection.organization_id == organization_id,
        )
    )
    connection = result.scalar_one_or_none()
    if connection is None:
        # 404, not 403: a connection in another organization must not be
        # distinguishable from one that does not exist.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="code host connection not found")
    return connection


@router.post("", response_model=VcsConnectionRead, status_code=status.HTTP_201_CREATED)
async def create_connection(
    organization_id: uuid.UUID,
    payload: VcsConnectionCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> VcsConnection:
    connection = VcsConnection(
        organization_id=organization_id,
        name=payload.name,
        provider=payload.provider.value,
        api_host=payload.api_host,
        token_env_var=payload.token_env_var,
        enabled=payload.enabled,
        created_by_user_id=membership.user_id,
    )

    # Resolved now, so a connection that could never post is refused here
    # rather than discovered during a review. This also reads the token, which
    # is why nothing below stores or returns it.
    try:
        destination_for(connection)
    except VcsError as exc:
        await record_event(
            db,
            action="vcs_connection.refused",
            resource_type="vcs_connection",
            result="deny",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"provider": payload.provider.value, "reason": str(exc)},
        )
        await db.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    db.add(connection)
    await db.flush()
    await record_event(
        db,
        action="vcs_connection.create",
        resource_type="vcs_connection",
        resource_id=str(connection.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"provider": connection.provider, "api_host": connection.api_host},
    )
    await db.commit()
    await db.refresh(connection)
    return connection


@router.get("", response_model=list[VcsConnectionRead])
async def list_connections(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> list[VcsConnection]:
    result = await db.execute(
        select(VcsConnection)
        .where(VcsConnection.organization_id == organization_id)
        .order_by(VcsConnection.created_at)
    )
    return list(result.scalars().all())


@router.patch("/{connection_id}", response_model=VcsConnectionRead)
async def update_connection(
    organization_id: uuid.UUID,
    connection_id: uuid.UUID,
    payload: VcsConnectionUpdate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> VcsConnection:
    connection = await _load(db, organization_id, connection_id)
    connection.enabled = payload.enabled
    await record_event(
        db,
        action="vcs_connection.update",
        resource_type="vcs_connection",
        resource_id=str(connection.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"enabled": connection.enabled},
    )
    await db.commit()
    await db.refresh(connection)
    return connection


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(
    organization_id: uuid.UUID,
    connection_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> None:
    connection = await _load(db, organization_id, connection_id)
    await record_event(
        db,
        action="vcs_connection.delete",
        resource_type="vcs_connection",
        resource_id=str(connection.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"provider": connection.provider, "name": connection.name},
    )
    await db.delete(connection)
    await db.commit()


@router.get("/{connection_id}/posts", response_model=list[PullRequestPostRead])
async def list_posts(
    organization_id: uuid.UUID,
    connection_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
    limit: int = 50,
) -> list[PullRequestPost]:
    await _load(db, organization_id, connection_id)
    result = await db.execute(
        select(PullRequestPost)
        .where(PullRequestPost.connection_id == connection_id)
        .order_by(PullRequestPost.created_at.desc())
        .limit(min(max(limit, 1), 200))
    )
    return list(result.scalars().all())


@router.post("/{connection_id}/publish", response_model=PullRequestPostRead)
async def publish_to_pull_request(
    organization_id: uuid.UUID,
    connection_id: uuid.UUID,
    payload: PublishRequest,
    db: DbSession,
    membership: Membership = Depends(_PUBLISHER),  # noqa: B008
) -> PullRequestPost:
    connection = await _load(db, organization_id, connection_id)
    if not connection.enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="this code host connection is disabled; enable it before publishing",
        )

    # Checked before anything is written: an unknown run id would otherwise
    # reach the foreign key as a 500, and a run id from another organization
    # must be indistinguishable from one that does not exist.
    run = (
        await db.execute(
            select(AssessmentRun).where(
                AssessmentRun.id == payload.run_id,
                AssessmentRun.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="assessment run not found")

    findings = await findings_for_run(db, organization_id, payload.run_id)
    post, _outcome = await publish(
        db,
        connection,
        repo=RepoRef(owner=payload.repo_owner, name=payload.repo_name),
        pull_number=payload.pull_number,
        head_sha=payload.head_sha,
        findings=findings,
        run_id=payload.run_id,
    )
    await db.commit()
    await db.refresh(post)
    # A failed post is still a 200 carrying the record: the caller asked us to
    # try, we tried, and the outcome (with its scrubbed reason) is the answer.
    # A 5xx would suggest the request was malformed, which it was not.
    return post
