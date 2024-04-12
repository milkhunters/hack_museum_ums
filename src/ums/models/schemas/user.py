import re
from datetime import datetime
from enum import Enum
from typing import NewType
from uuid import UUID

from pydantic import BaseModel, field_validator, EmailStr

from .role import Role


class UserState(str, Enum):
    NOT_CONFIRMED = "NOT_CONFIRMED"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    DELETED = "DELETED"


# class AvatarFileType(str, Enum):
#     PHOTO_JPEG = "image/jpeg"
#     PHOTO_PNG = "image/png"
#     PHOTO_GIF = "image/gif"


UserID = NewType('UserID', UUID)


def is_valid_password(password: str) -> bool:
    pattern = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,32}$"
    return re.match(pattern, password) is not None


def is_valid_first_name(first_name: str) -> bool:
    pattern = r"^[a-zA-Zа-яА-Я]+(?: [a-zA-Zа-яА-Я]+)*$"
    return (re.match(pattern, first_name) is not None) and len(first_name) <= 100


def is_valid_last_name(last_name: str) -> bool:
    pattern = r"^[a-zA-Zа-яА-Я]+(?: [a-zA-Zа-яА-Я]+)*$"
    return (re.match(pattern, last_name) is not None) and len(last_name) <= 100


class User(BaseModel):
    id: UserID
    email: EmailStr
    first_name: str
    last_name: str
    role: Role
    state: UserState

    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

    @field_validator('password')
    def password_must_be_valid(cls, value):
        if not is_valid_password(value):
            raise ValueError("Пароль должен быть валидным")
        return value

    @field_validator('first_name')
    def first_name_must_be_valid(cls, value):
        if not is_valid_first_name(value):
            raise ValueError("Имя должно быть валидным")
        return value

    @field_validator('last_name')
    def last_name_must_be_valid(cls, value):
        if not is_valid_last_name(value):
            raise ValueError("Фамилия должна быть валидной")
        return value


class UserAuth(BaseModel):
    email: EmailStr
    password: str

    @field_validator('password')
    def password_must_be_valid(cls, value):
        if not is_valid_password(value):
            raise ValueError("Пароль должен быть валидным")
        return value


class UserUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None

    @field_validator('first_name')
    def first_name_must_be_valid(cls, value):
        if value and not is_valid_first_name(value):
            raise ValueError("Имя должно быть валидным")
        return value

    @field_validator('last_name')
    def last_name_must_be_valid(cls, value):
        if value and not is_valid_last_name(value):
            raise ValueError("Фамилия должна быть валидной")
        return value


class UserUpdateByAdmin(UserUpdate):
    email: EmailStr = None
    role_id: UUID = None
    state: UserState = None
