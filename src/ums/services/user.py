import asyncio
import uuid

from ums import exceptions
from ums.config import JWTConfig
from ums.models import schemas
from ums.models.auth import BaseUser
from ums.models.schemas import UserState
from ums.roles.permission import Permission
from ums.security.filters import permission_filter, state_filter
from ums.security.session import SessionManager
from ums.security.utils import verify_password, get_hashed_password
from ums.repositories import UserRepo, RoleRepo
from ums.utils import RedisClient


class UserApplicationService:

    def __init__(
            self,
            current_user: BaseUser,
            *,
            user_repo: UserRepo,
            role_repo: RoleRepo,
            redis_client_reauth: RedisClient,
            session: SessionManager,
            config: JWTConfig,
    ):
        self._current_user = current_user
        self._repo = user_repo
        self._role_repo = role_repo
        self._redis_client_reauth = redis_client_reauth
        self._session = session
        self._config = config

    @permission_filter(Permission.GET_SELF)
    @state_filter(UserState.ACTIVE)
    async def get_me(self) -> schemas.User:
        user = await self._repo.get(id=self._current_user.id, as_full=True)
        return schemas.User.model_validate(user)

    @permission_filter(Permission.GET_USER)
    async def get_user(self, user_id: uuid.UUID) -> schemas.User:
        user = await self._repo.get(id=user_id, as_full=True)
        if not user:
            raise exceptions.NotFound(f"Пользователь с id:{user_id} не найден!")
        return schemas.User.model_validate(user)

    @permission_filter(Permission.UPDATE_SELF)
    @state_filter(UserState.ACTIVE)
    async def update_me(self, data: schemas.UserUpdate) -> None:
        await self._repo.update(
            id=self._current_user.id,
            **data.model_dump(exclude_unset=True)
        )

    @permission_filter(Permission.UPDATE_USER)
    @state_filter(UserState.ACTIVE)
    async def update_user(self, user_id: uuid.UUID, data: schemas.UserUpdateByAdmin) -> None:
        user = await self._repo.get(id=user_id)
        if not user:
            raise exceptions.NotFound(f"Пользователь с id:{user_id} не найден!")

        if data.role_id:
            role = await self._role_repo.get(id=data.role_id)
            if not role:
                raise exceptions.NotFound(f"Роль с id:{data.role_id} не найдена!")

        if data.state or data.role_id:
            session_id_list = await self._session.get_user_sessions(user_id)
            await asyncio.gather(
                self._redis_client_reauth.set(
                    session_id, data["refresh_token"], expire=self._config.ACCESS_EXP_SEC
                ) for session_id, data in session_id_list.items()
            )

        await self._repo.update(
            id=user_id,
            **data.model_dump(exclude_unset=True)
        )

    @permission_filter(Permission.UPDATE_SELF)
    @state_filter(UserState.ACTIVE)
    async def update_password(self, old_password: str, new_password: str) -> None:
        if old_password == new_password:
            raise exceptions.BadRequest("Новый пароль не должен совпадать со старым!")

        user = await self._repo.get(id=self._current_user.id)
        if not verify_password(old_password, user.hashed_password):
            raise exceptions.BadRequest("Неверный пользовательский пароль!")

        if not schemas.user.is_valid_password(new_password):
            raise exceptions.BadRequest("Неверный формат пароля!")

        await self._repo.update(
            id=self._current_user.id,
            hashed_password=get_hashed_password(new_password)
        )

    @permission_filter(Permission.DELETE_SELF)
    @state_filter(UserState.ACTIVE)
    async def delete_me(self, password: str) -> None:
        user = await self._repo.get(id=self._current_user.id)
        if not verify_password(password, user.hashed_password):
            raise exceptions.BadRequest("Неверный пароль!")

        await self._repo.update(
            id=self._current_user.id,
            state=UserState.DELETED
        )

    @permission_filter(Permission.GET_SELF_SESSIONS)
    @state_filter(UserState.ACTIVE)
    async def get_my_sessions(self) -> list[schemas.Session]:
        session_id_list = await self._session.get_user_sessions(self._current_user.id)
        return [
            schemas.Session(
                id=session_id,
                ip=data["ip"],
                time=data["time"],
                user_agent=data["user_agent"]
            )
            for session_id, data in session_id_list.items()
        ]

    @permission_filter(Permission.GET_USER_SESSIONS)
    @state_filter(UserState.ACTIVE)
    async def get_user_sessions(self, user_id: uuid.UUID) -> list[schemas.Session]:
        session_id_list = await self._session.get_user_sessions(user_id)
        return [
            schemas.Session(
                id=session_id,
                ip=data["ip"],
                time=data["time"],
                user_agent=data["user_agent"]
            )
            for session_id, data in session_id_list.items()
        ]

    @permission_filter(Permission.DELETE_SELF_SESSION)
    @state_filter(UserState.ACTIVE)
    async def delete_self_session(self, session_id: str) -> None:
        session_data = await self._session.get_data_from_session(str(self._current_user.id), session_id)
        await self._session.delete_session(self._current_user.id, session_id)
        await self._redis_client_reauth.set(
            session_id, session_data["refresh_token"], expire=self._config.ACCESS_EXP_SEC
        )

    @permission_filter(Permission.DELETE_USER_SESSION)
    @state_filter(UserState.ACTIVE)
    async def delete_user_session(self, user_id: uuid.UUID, session_id: str) -> None:
        session_data = await self._session.get_data_from_session(str(user_id), session_id)
        await self._session.delete_session(user_id, session_id)
        await self._redis_client_reauth.set(
            session_id, session_data["refresh_token"], expire=self._config.ACCESS_EXP_SEC
        )
