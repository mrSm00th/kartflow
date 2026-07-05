import random
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

import app.modules.users.models as models
from app.core.auth import (
    CurrentUser,
    create_access_token,
    create_refresh_token,
    get_valid_refresh_token_row,
    hash_password,
    hash_refresh_token,
    store_refresh_token,
    verify_password,
)
from app.core.config import settings
from app.core.dependencies import require_roles
from app.core.email import send_otp_email, send_password_reset_email
from app.db.database import get_db
from app.modules.restaurants.models import Restaurant
from app.modules.users.models import OTPPurpose, OTPVerification, User, UserRole
from app.modules.users.schemas import (
    MessageResponse,
    PaginatedOwnerRestaurant,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RestaurantList,
    SendOTPRequest,
    Token,
    UserCreate,
    UserPrivate,
    VerifyEmailRequest,
)

router = APIRouter(prefix="/users", tags=["users"])


#  helpes


def _generate_otp(length: int = 6) -> str:
    """Generating a Cryptographically random numeric OTP."""
    return "".join(random.SystemRandom().choices(string.digits, k=length))


async def _invalidate_existing_otps(
    db: AsyncSession,
    user_id: uuid.UUID,
    purpose: OTPPurpose,
) -> None:
    """Mark all existing unused OTPs for this user + purpose as used
    before issuing a new one."""
    result = await db.execute(
        select(OTPVerification).where(
            OTPVerification.user_id == user_id,
            OTPVerification.purpose == purpose,
            OTPVerification.is_used == False,
        )
    )
    for record in result.scalars().all():
        record.is_used = True
    await db.flush()


async def _get_valid_otp_record(
    db: AsyncSession,
    user_id: uuid.UUID,
    purpose: OTPPurpose,
) -> OTPVerification | None:
    """Fetch the latest unused unexpired record for this user + purpose."""
    result = await db.execute(
        select(OTPVerification)
        .where(
            OTPVerification.user_id == user_id,
            OTPVerification.purpose == purpose,
            OTPVerification.is_used == False,
            OTPVerification.expires_at > datetime.now(UTC),
        )
        .order_by(OTPVerification.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


#  user registration


@router.post(
    "",
    response_model=UserPrivate,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    user: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):

    result = await db.execute(
        select(models.User).where(
            func.lower(models.User.full_name) == user.full_name.lower()
        )
    )
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this full name already exists",
        )

    result = await db.execute(
        select(models.User).where(
            func.lower(models.User.email) == user.email  # already lowercased
        )
    )
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )

    result = await db.execute(
        select(models.User).where(models.User.phone_number == user.phone_number)
    )
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this phone number already exists",
        )

    new_user = models.User(
        full_name=user.full_name,
        email=user.email,  # already normalized by schema
        phone_number=user.phone_number,
        password_hash=hash_password(user.password),
    )

    db.add(new_user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email, phone number, or full name already exists",
        )

    await db.refresh(new_user)
    return new_user


# login


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(models.User).where(models.User.email == form_data.username)
    )
    user = result.scalars().first()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )

    raw_refresh_token = create_refresh_token()
    await store_refresh_token(db, user.id, raw_refresh_token)
    await db.commit()

    return Token(
        access_token=access_token,
        refresh_token=raw_refresh_token,
        token_type="bearer",
    )


@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    data: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    token_row = await get_valid_refresh_token_row(db, data.refresh_token)

    if not token_row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await db.get(models.User, token_row.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # rotation: kill the old refresh token, issue a brand new one
    token_row.revoked = True

    new_access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    new_raw_refresh_token = create_refresh_token()
    await store_refresh_token(db, user.id, new_raw_refresh_token)
    await db.commit()

    return Token(
        access_token=new_access_token,
        refresh_token=new_raw_refresh_token,
        token_type="bearer",
    )


@router.post("/logout", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def logout(
    data: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    token_row = await get_valid_refresh_token_row(db, data.refresh_token)

    if token_row:
        token_row.revoked = True
        await db.commit()

    # same response for security purpose
    return MessageResponse(message="Logged out successfully.")


@router.post(
    "/logout-all", response_model=MessageResponse, status_code=status.HTTP_200_OK
)
async def logout_all_devices(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(models.RefreshToken).where(
            models.RefreshToken.user_id == current_user.id,
            models.RefreshToken.revoked == False,
        )
    )
    for row in result.scalars().all():
        row.revoked = True

    await db.commit()
    return MessageResponse(message="Logged out from all devices.")


# current user


@router.get("/me", response_model=UserPrivate)
async def get_current_user(current_user: CurrentUser):
    return current_user


@router.get("/me/restaurants", response_model=PaginatedOwnerRestaurant)
async def get_current_user_restaurants(
    current_user: Annotated[User, Depends(require_roles(UserRole.RESTAURANT_OWNER))],
    db: Annotated[AsyncSession, Depends(get_db)],
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = settings.restaurants_per_page,
):
    result = await db.execute(
        select(func.count())
        .select_from(Restaurant)
        .where(Restaurant.owner_id == current_user.id)
    )
    total = result.scalar() or 0

    result = await db.execute(
        select(Restaurant)
        .options(selectinload(Restaurant.primary_image))
        .where(Restaurant.owner_id == current_user.id)
        .order_by(Restaurant.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    restaurants = result.scalars().all()

    return PaginatedOwnerRestaurant(
        restaurants=[RestaurantList.model_validate(r) for r in restaurants],
        total=total,
        skip=skip,
        limit=limit,
        has_more=skip + len(restaurants) < total,
    )


# email verification


@router.post(
    "/verify-email/send",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Send email verification OTP",
    description=(
        "Sends a 6-digit OTP to the given email. "
        "Any previously issued unused OTPs for this user are invalidated. "
        "Returns the same response whether the email exists or not for security issues."
    ),
)
async def send_verification_otp(
    data: SendOTPRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(models.User).where(models.User.email == data.email)
    )
    user = result.scalars().first()

    # same response either way — don't reveal whether email is registered
    if not user or user.is_account_verified:
        return MessageResponse(
            message="If this email is registered and unverified, an OTP has been sent."
        )

    await _invalidate_existing_otps(db, user.id, OTPPurpose.EMAIL_VERIFICATION)

    otp = _generate_otp()
    db.add(
        OTPVerification(
            user_id=user.id,
            otp_hash=hash_password(otp),
            purpose=OTPPurpose.EMAIL_VERIFICATION,
            expires_at=datetime.now(UTC)
            + timedelta(minutes=settings.otp_expire_minutes),
        )
    )
    await db.commit()

    try:
        await send_otp_email(
            to_email=user.email,
            full_name=user.full_name,
            otp=otp,
        )
    except Exception:
        # OTP is saved in DB — user can request again if email fails
        pass

    return MessageResponse(
        message="If this email is registered and unverified, an OTP has been sent."
    )


@router.post(
    "/verify-email/confirm",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Confirm email verification OTP",
    description="Verifies the 6-digit OTP and marks the account as verified.",
)
async def confirm_verification_otp(
    data: VerifyEmailRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(models.User).where(models.User.email == data.email)
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if user.is_account_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already verified.",
        )

    otp_record = await _get_valid_otp_record(db, user.id, OTPPurpose.EMAIL_VERIFICATION)

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP is invalid or has expired. Please request a new one.",
        )

    if not verify_password(data.otp, otp_record.otp_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect OTP.",
        )

    otp_record.is_used = True
    user.is_account_verified = True
    await db.commit()

    return MessageResponse(message="Email verified successfully.")


# password reset


@router.post(
    "/password-reset/request",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Request password reset link",
    description=(
        "Sends a password reset link to the given email. "
        "Link contains a secure token valid for otp_expire_minutes. "
        "Returns the same response whether the email exists or not for security reason."
    ),
)
async def request_password_reset(
    data: PasswordResetRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(models.User).where(models.User.email == data.email)
    )
    user = result.scalars().first()

    if not user:
        return MessageResponse(
            message="If this email is registered, a password reset link has been sent."
        )

    await _invalidate_existing_otps(db, user.id, OTPPurpose.PASSWORD_RESET)

    # 32-byte URL-safe token — far stronger than a 6-digit OTP
    reset_token = secrets.token_urlsafe(32)

    db.add(
        OTPVerification(
            user_id=user.id,
            otp_hash=hash_password(reset_token),
            purpose=OTPPurpose.PASSWORD_RESET,
            expires_at=datetime.now(UTC)
            + timedelta(minutes=settings.otp_expire_minutes),
        )
    )
    await db.commit()

    try:
        await send_password_reset_email(
            to_email=user.email,
            full_name=user.full_name,
            reset_token=reset_token,
        )
    except Exception:
        pass

    return MessageResponse(
        message="If this email is registered, a password reset link has been sent."
    )


@router.post(
    "/password-reset/confirm",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Confirm reset token and set new password",
    description=(
        "Receives the token from the reset link (plus the email embedded in that link) "
        "and sets the new password if the token is valid and unexpired."
    ),
)
async def confirm_password_reset(
    data: PasswordResetConfirm,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(models.User).where(models.User.email == data.email)
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    otp_record = await _get_valid_otp_record(db, user.id, OTPPurpose.PASSWORD_RESET)

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset link is invalid or has expired. Please request a new one.",
        )

    if not verify_password(data.token, otp_record.otp_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset link is invalid or has expired. Please request a new one.",
        )

    otp_record.is_used = True
    user.password_hash = hash_password(data.new_password)
    await db.commit()

    return MessageResponse(message="Password reset successfully. You can now log in.")
