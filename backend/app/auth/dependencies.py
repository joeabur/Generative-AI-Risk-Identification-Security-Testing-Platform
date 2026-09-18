import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.security import InvalidTokenError, decode_access_token
from app.core.config import get_settings
from app.db.session import get_db
from app.models.organization import Membership, Role
from app.models.user import User

DbSession = Annotated[AsyncSession, Depends(get_db)]


def _extract_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[7:]
    settings = get_settings()
    return request.cookies.get(settings.session_cookie_name)


async def get_current_user(request: Request, db: DbSession) -> User:
    token = _extract_token(request)
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = decode_access_token(token)
    except InvalidTokenError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        ) from exc

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject") from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_membership(
    minimum_role: Role = Role.VIEWER,
) -> Callable[[uuid.UUID, User, AsyncSession], Awaitable[Membership]]:
    """Dependency factory enforcing RBAC on an `organization_id` path parameter.

    A user who is not a member of the organization gets 404, not 403 — this
    avoids confirming the organization exists to a caller with no legitimate
    reason to know, and is the behaviour the tenant-isolation tests in
    docs/BUILD_SPEC.md §24 assert on ("wrong organization -> BLOCKED").
    """

    async def dependency(
        organization_id: uuid.UUID, current_user: CurrentUser, db: DbSession
    ) -> Membership:
        result = await db.execute(
            select(Membership)
            .where(
                Membership.organization_id == organization_id,
                Membership.user_id == current_user.id,
            )
            .options(selectinload(Membership.organization))
        )
        membership = result.scalar_one_or_none()
        if membership is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
        if not membership.role.at_least(minimum_role):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum_role.value}' or higher",
            )
        return membership

    return dependency
