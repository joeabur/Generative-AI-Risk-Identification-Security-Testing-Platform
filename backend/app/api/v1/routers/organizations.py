import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.audit.service import record_event
from app.auth.dependencies import CurrentUser, DbSession, require_membership
from app.models.organization import Membership, Organization, Role
from app.models.user import User
from app.schemas.organization import (
    MembershipInvite,
    MembershipRead,
    OrganizationCreate,
    OrganizationRead,
)

router = APIRouter(prefix="/organizations", tags=["organizations"])

_SLUG_INVALID_CHARS = re.compile(r"[^a-z0-9-]+")


def _slugify(name: str) -> str:
    base = _SLUG_INVALID_CHARS.sub("-", name.lower()).strip("-") or "org"
    return f"{base}-{uuid.uuid4().hex[:8]}"


@router.post("", response_model=OrganizationRead, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate, request: Request, current_user: CurrentUser, db: DbSession
) -> OrganizationRead:
    org = Organization(name=payload.name, slug=_slugify(payload.name))
    db.add(org)
    await db.flush()

    membership = Membership(user_id=current_user.id, organization_id=org.id, role=Role.OWNER)
    db.add(membership)
    await db.flush()

    await record_event(
        db,
        action="organization.create",
        resource_type="organization",
        resource_id=str(org.id),
        result="allow",
        organization_id=org.id,
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return OrganizationRead(id=org.id, name=org.name, slug=org.slug, role=Role.OWNER)


@router.get("", response_model=list[OrganizationRead])
async def list_organizations(current_user: CurrentUser, db: DbSession) -> list[OrganizationRead]:
    result = await db.execute(
        select(Membership)
        .where(Membership.user_id == current_user.id)
        .options(selectinload(Membership.organization))
    )
    memberships = result.scalars().all()
    return [
        OrganizationRead(
            id=m.organization.id, name=m.organization.name, slug=m.organization.slug, role=m.role
        )
        for m in memberships
    ]


@router.get("/{organization_id}", response_model=OrganizationRead)
async def get_organization(
    organization_id: uuid.UUID,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> OrganizationRead:
    org = membership.organization
    return OrganizationRead(id=org.id, name=org.name, slug=org.slug, role=membership.role)


@router.get("/{organization_id}/members", response_model=list[MembershipRead])
async def list_members(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[MembershipRead]:
    result = await db.execute(
        select(Membership)
        .where(Membership.organization_id == organization_id)
        .options(selectinload(Membership.user))
    )
    members = result.scalars().all()
    return [
        MembershipRead(
            id=m.id, user_id=m.user_id, email=m.user.email, full_name=m.user.full_name, role=m.role
        )
        for m in members
    ]


@router.post(
    "/{organization_id}/members", response_model=MembershipRead, status_code=status.HTTP_201_CREATED
)
async def invite_member(
    organization_id: uuid.UUID,
    payload: MembershipInvite,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> MembershipRead:
    """Add an existing user to the organization by email.

    Only Owner/Admin may grant membership, per docs/BUILD_SPEC.md §17.2. This
    Phase-1 version requires the invitee to already have an account; email
    invitations for not-yet-registered users are deferred (docs/roadmap.md).
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    invitee = result.scalar_one_or_none()
    if invitee is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No registered user with that email")

    existing = await db.execute(
        select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == invitee.id
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="User is already a member")

    new_membership = Membership(
        user_id=invitee.id, organization_id=organization_id, role=payload.role
    )
    db.add(new_membership)
    await db.flush()

    await record_event(
        db,
        action="organization.member_added",
        resource_type="membership",
        resource_id=str(new_membership.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"invitee_id": str(invitee.id), "role": payload.role.value},
    )
    await db.commit()

    return MembershipRead(
        id=new_membership.id,
        user_id=invitee.id,
        email=invitee.email,
        full_name=invitee.full_name,
        role=new_membership.role,
    )
