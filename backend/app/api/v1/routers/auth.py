from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from app.audit.service import record_event
from app.auth.dependencies import CurrentUser, DbSession
from app.auth.security import create_access_token, hash_password, verify_password
from app.core.config import get_settings
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserRead

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest, request: Request, response: Response, db: DbSession
) -> TokenResponse:
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none() is not None:
        await record_event(
            db,
            action="auth.register",
            resource_type="user",
            result="deny",
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "email_already_registered"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Email is already registered")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()

    token = create_access_token(subject=user.id)
    await record_event(
        db,
        action="auth.register",
        resource_type="user",
        resource_id=str(user.id),
        result="allow",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    _set_session_cookie(response, token)
    return TokenResponse(access_token=token, user=UserRead.model_validate(user))


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest, request: Request, response: Response, db: DbSession
) -> TokenResponse:
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.password_hash):
        await record_event(
            db,
            action="auth.login",
            resource_type="user",
            result="deny",
            ip_address=request.client.host if request.client else None,
            metadata={"email": payload.email},
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_active:
        await record_event(
            db,
            action="auth.login",
            resource_type="user",
            resource_id=str(user.id),
            result="deny",
            user_id=user.id,
            metadata={"reason": "inactive_account"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Account is inactive")

    token = create_access_token(subject=user.id)
    await record_event(
        db,
        action="auth.login",
        resource_type="user",
        resource_id=str(user.id),
        result="allow",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    _set_session_cookie(response, token)
    return TokenResponse(access_token=token, user=UserRead.model_validate(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response, current_user: CurrentUser, db: DbSession) -> None:
    await record_event(
        db,
        action="auth.logout",
        resource_type="user",
        resource_id=str(current_user.id),
        result="allow",
        user_id=current_user.id,
    )
    await db.commit()
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")


@router.get("/me", response_model=UserRead)
async def me(current_user: CurrentUser) -> UserRead:
    return UserRead.model_validate(current_user)
