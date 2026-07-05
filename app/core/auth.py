import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db

# import app.db.models as models
from app.modules.users.models import RefreshToken, User

password_hash = PasswordHash.recommended()

oauth_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/token")


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:

    return password_hash.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:

    # NOTE: Copying data as py dicts are mutable and are passed by reference,
    #  we don't want to modify the original data dict
    to_encode = data.copy()

    if expires_delta:

        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=settings.access_token_expire_minutes
        )

    to_encode.update({"exp": expire})
    # NOTE: sub will be added in the caller func and contains the user_id

    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key.get_secret_value(), algorithm=settings.algorithm
    )

    return encoded_jwt


def verify_access_token(token: str) -> str | None:

    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=settings.algorithm,
            options={"require": ["exp", "sub"]},
        )

    except jwt.InvalidTokenError:
        return None

    else:
        return payload.get("sub")


async def get_current_user(
    token: Annotated[str, Depends(oauth_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:

    user_id = verify_access_token(token)

    if user_id is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or Expired Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:

        user_id_uuid = uuid.UUID(user_id)

    except (TypeError, ValueError):

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or Expired Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id_uuid))

    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or Expired Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def get_current_user_ws(
    token: Annotated[str, Depends(oauth_scheme)],  # reads Authorization header
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await db.get(User, uuid.UUID(user_id))

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# refresh toen functions


def create_refresh_token() -> str:

    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:

    return password_hash.hash(token)


def verify_refresh_token(plain_token: str, hashed_token: str) -> bool:

    password_hash.verify(plain_token, hashed_token)


async def store_refresh_token(
    db: AsyncSession,
    user_id: uuid.UUID,
    raw_token: str,
) -> RefreshToken:

    token_row = RefreshToken(
        user_id=user_id,
        token=hash_refresh_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(settings.refresh_token_expire_days),
    )

    db.add(token_row)
    await db.flush()

    return token_row


async def get_valid_refresh_token_row(
    db: AsyncSession,
    raw_token: str,
) -> RefreshToken | None:

    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(UTC),
        )
    )

    candidates = result.scalars().all()

    for row in candidates:

        if verify_refresh_token(raw_token, row.token):
            return row

    return None
