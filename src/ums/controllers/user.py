import uuid

from fastapi import APIRouter, Depends
from fastapi import status as http_status
from fastapi.requests import Request
from fastapi.responses import Response

from ums.dependencies.services import get_services
from ums.models import schemas
from ums.services import ServiceFactory
from ums.views import SessionsResponse
from ums.views.user import UserResponse

router = APIRouter()


@router.get("", response_model=UserResponse, status_code=http_status.HTTP_200_OK)
async def get_self(services: ServiceFactory = Depends(get_services)):
    """
    Получить модель текущего пользователя

    Требуемые права доступа: GET_SELF

    Состояние: ACTIVE
    """
    return UserResponse(content=await services.user.get_me())


@router.put("", response_model=None, status_code=http_status.HTTP_204_NO_CONTENT)
async def update_self(data: schemas.UserUpdate, services: ServiceFactory = Depends(get_services)):
    """
    Обновить данные текущего пользователя

    Требуемые права доступа: UPDATE_SELF

    Состояние: ACTIVE
    """
    await services.user.update_me(data)


@router.put("/password", response_model=None, status_code=http_status.HTTP_204_NO_CONTENT)
async def update_self_password(old_password: str, new_password: str, services: ServiceFactory = Depends(get_services)):
    """
    Обновить пароль текущего пользователя

    Требуемые права доступа: UPDATE_SELF

    Состояние: ACTIVE

    """
    await services.user.update_password(old_password, new_password)


@router.delete("", response_model=None, status_code=http_status.HTTP_204_NO_CONTENT)
async def delete_self(
        password: str,
        request: Request,
        response: Response,
        services: ServiceFactory = Depends(get_services)
):
    """
    Удалить текущего пользователя

    Требуемые права доступа: DELETE_SELF, LOGOUT

    Состояние: ACTIVE
    """
    await services.user.delete_me(password)
    await services.auth.logout(request, response)


@router.get("/sessions", response_model=SessionsResponse, status_code=http_status.HTTP_200_OK)
async def get_self_sessions(services: ServiceFactory = Depends(get_services)):
    """
    Получить список сессий текущего пользователя

    Требуемые права доступа: GET_SELF_SESSIONS

    Состояние: ACTIVE
    """
    return SessionsResponse(content=await services.user.get_my_sessions())


@router.get("/sessions/{user_id}", response_model=SessionsResponse, status_code=http_status.HTTP_200_OK)
async def get_user_sessions(user_id: uuid.UUID, services: ServiceFactory = Depends(get_services)):
    """
    Получить список сессий пользователя по id

    Требуемые права доступа: GET_USER_SESSIONS

    Состояние: ACTIVE
    """
    return SessionsResponse(content=await services.user.get_user_sessions(user_id))


@router.delete("/sessions", response_model=None, status_code=http_status.HTTP_204_NO_CONTENT)
async def delete_self_session(session_id: str, services: ServiceFactory = Depends(get_services)):
    """
    Удалить свою сессию по id

    Требуемые права доступа: DELETE_SELF_SESSION

    Состояние: ACTIVE
    """
    await services.user.delete_self_session(session_id)


@router.delete("/sessions/{user_id}", response_model=None, status_code=http_status.HTTP_204_NO_CONTENT)
async def delete_user_session(user_id: uuid.UUID, session_id: str, services: ServiceFactory = Depends(get_services)):
    """
    Удалить сессию пользователя по id

    Требуемые права доступа: DELETE_USER_SESSION

    Состояние: ACTIVE
    """
    await services.user.delete_user_session(user_id, session_id)


@router.get("/{user_id}", response_model=UserResponse, status_code=http_status.HTTP_200_OK)
async def get_user(user_id: uuid.UUID, services: ServiceFactory = Depends(get_services)):
    """
    Получить модель пользователя по id

    Требуемые права доступа: GET_USER
    """
    return UserResponse(content=await services.user.get_user(user_id))


@router.put("/{user_id}", response_model=None, status_code=http_status.HTTP_204_NO_CONTENT)
async def update_user(
        user_id: uuid.UUID,
        data: schemas.UserUpdateByAdmin,
        services: ServiceFactory = Depends(get_services)
):
    """
    Обновить данные пользователя по id

    Требуемые права доступа: UPDATE_USER

    Состояние: ACTIVE
    """
    await services.user.update_user(user_id, data)
