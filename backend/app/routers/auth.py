
import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_active_user, rate_limit_auth
from app.core.security import (
    create_token_pair,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.user import (
    TokenRefresh,
    TokenResponse,
    TwoFactorSetupResponse,
    TwoFactorVerify,
    UserCreate,
    UserLogin,
    UserResponse,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_auth),
) -> UserResponse:
    """Register a new user."""
    existing = await db.execute(select(User).where(User.email == user_data.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        )

    user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        is_active=True,
        tier="free",
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    return UserResponse.model_validate(user)


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_auth),
) -> TokenResponse:
    """Login and get access + refresh tokens."""
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated"
        )

    if user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_200_OK,
            detail="2FA required",
            headers={"X-2FA-Required": "true", "X-User-ID": str(user.id)},
        )

    tokens = create_token_pair(
        subject=str(user.id), extra_claims={"email": user.email, "tier": user.tier}
    )
    return TokenResponse(**tokens)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    body: TokenRefresh,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Refresh access token using refresh token."""
    payload = decode_token(body.refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
        )

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive"
        )

    tokens = create_token_pair(
        subject=str(user.id), extra_claims={"email": user.email, "tier": user.tier}
    )
    return TokenResponse(**tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    current_user: User = Depends(get_current_active_user),
) -> None:
    """Logout (client should discard tokens)."""
    pass


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> TwoFactorSetupResponse:
    """Set up 2FA TOTP."""
    secret = pyotp.random_base32()
    current_user.two_factor_secret = secret
    db.add(current_user)
    await db.flush()

    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(
        name=current_user.email, issuer_name="PhishGuard AI"
    )

    return TwoFactorSetupResponse(secret=secret, otpauth_url=otpauth_url)


@router.post("/2fa/verify")
async def verify_2fa(
    body: TwoFactorVerify,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _rate: None = Depends(rate_limit_auth),
) -> TokenResponse:
    """Verify 2FA code and complete login."""
    user_id = request.headers.get("X-User-ID")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing user ID"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA setup"
        )

    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code"
        )

    tokens = create_token_pair(
        subject=str(user.id), extra_claims={"email": user.email, "tier": user.tier}
    )
    return TokenResponse(**tokens)


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Get current user profile."""
    return UserResponse.model_validate(current_user)
