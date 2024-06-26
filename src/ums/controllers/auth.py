from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi import status as http_status
from fastapi.requests import Request
from fastapi.responses import Response

from ums.config import JWTConfig
from ums.dependencies.config import get_jwt_config
from ums.dependencies.services import get_services
from ums.models import schemas
from ums.services import ServiceFactory
from ums.views import UserResponse

router = APIRouter()


@router.post("/signUp", response_model=None, status_code=http_status.HTTP_201_CREATED)
async def sign_up(data: schemas.UserCreate, services: ServiceFactory = Depends(get_services)):
    """
    Регистрация нового пользователя

    Требуемые права доступа: CREATE_USER
    """
    await services.auth.create_user(data)


@router.post("/signIn", response_model=UserResponse, status_code=http_status.HTTP_200_OK)
async def sign_in(
        user: schemas.UserAuth,
        response: Response,
        services: Annotated[ServiceFactory, Depends(get_services)],
        config: Annotated[JWTConfig, Depends(get_jwt_config)]
):
    """
    Вход в систему

    Требуемые права доступа: AUTHENTICATE
    """
    content, jwt_tokens, session_id = await services.auth.authenticate(user)
    response.set_cookie(
        key="access_token",
        value=jwt_tokens[0],
        secure=True,
        httponly=True,
        samesite="none",
        max_age=config.ACCESS_EXP_SEC,
        path="/api"
    )
    response.set_cookie(
        key="refresh_token",
        value=jwt_tokens[1],
        secure=True,
        httponly=True,
        samesite="none",
        max_age=config.REFRESH_EXP_SEC,
        path="/api",
    )
    response.set_cookie(
        key="session_id",
        value=session_id,
        secure=True,
        httponly=True,
        samesite="none",
        max_age=config.REFRESH_EXP_SEC,
        path="/api"
    )

    return UserResponse(content=content)


@router.post('/logout', response_model=None, status_code=http_status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, services: ServiceFactory = Depends(get_services)):
    """
    Выход из системы

    Требуемые права доступа: LOGOUT
    """
    response.set_cookie(
        key="access_token",
        value="",
        secure=True,
        httponly=True,
        samesite="none",
        max_age=1,
        path="/api"
    )
    response.set_cookie(
        key="refresh_token",
        value="",
        secure=True,
        httponly=True,
        samesite="none",
        max_age=1,
        path="/api",
    )
    response.set_cookie(
        key="session_id",
        value="",
        secure=True,
        httponly=True,
        samesite="none",
        max_age=1,
        path="/api"
    )
    session_id = request.cookies.get("session_id")
    await services.auth.logout(session_id)


@router.post('/refresh_tokens', response_model=UserResponse, status_code=http_status.HTTP_200_OK)
async def refresh(
        request: Request,
        response: Response,
        services: Annotated[ServiceFactory, Depends(get_services)],
        config: Annotated[JWTConfig, Depends(get_jwt_config)]
):
    """
    Обновить токены jwt

    Требуемые права доступа: None
    Состояние: ACTIVE
    """
    jwt_tokens = (
        request.cookies.get("access_token"),
        request.cookies.get("refresh_token")
    )
    session_id = request.cookies.get("session_id")

    content, new_jwt_tokens, new_session_id = await services.auth.refresh_tokens(jwt_tokens, session_id)
    response.set_cookie(
        key="access_token",
        value=new_jwt_tokens[0],
        secure=True,
        httponly=True,
        samesite="none",
        max_age=config.ACCESS_EXP_SEC,
        path="/api"
    )
    response.set_cookie(
        key="refresh_token",
        value=new_jwt_tokens[1],
        secure=True,
        httponly=True,
        samesite="none",
        max_age=config.REFRESH_EXP_SEC,
        path="/api",
    )
    response.set_cookie(
        key="session_id",
        value=new_session_id,
        secure=True,
        httponly=True,
        samesite="none",
        max_age=config.REFRESH_EXP_SEC,
        path="/api"
    )
    return UserResponse(content=content)
