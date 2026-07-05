import uuid
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.modules.restaurants.models import RestaurantStatus
from app.modules.users.models import UserRole, UserStatus


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseSchema):
    full_name: Annotated[str, Field(min_length=3, max_length=100)]
    email: EmailStr
    phone_number: Annotated[str, Field(min_length=7, max_length=15)]
    password: Annotated[str, Field(min_length=8, max_length=128)]

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("full_name", mode="before")
    @classmethod
    def strip_full_name(cls, v: str) -> str:
        return v.strip()


class UserPublic(BaseSchema):
    full_name: str
    role: UserRole
    user_status: UserStatus
    is_account_verified: bool


class UserPrivate(UserPublic):
    email: EmailStr
    phone_number: str


class RestaurantList(BaseSchema):
    id: uuid.UUID
    name: str
    address_line_1: str
    city: str
    state: str
    status: RestaurantStatus


class PaginatedOwnerRestaurant(BaseSchema):
    restaurants: list[RestaurantList]
    total: int
    skip: int
    limit: int
    has_more: bool


class CuisineRequestHistroryResponse(BaseSchema):
    id: uuid.UUID
    cuisine_name: str


# =========================
# AUTH FLOW SCHEMAS
# =========================


class MessageResponse(BaseSchema):
    message: str


# email verification


class SendOTPRequest(BaseSchema):
    email: EmailStr


class VerifyEmailRequest(BaseSchema):
    email: EmailStr
    otp: Annotated[str, Field(min_length=6, max_length=6)]


# password reset


class PasswordResetRequest(BaseSchema):
    email: EmailStr


class PasswordResetConfirm(BaseSchema):
    email: EmailStr
    token: str
    new_password: Annotated[str, Field(min_length=8, max_length=128)]
