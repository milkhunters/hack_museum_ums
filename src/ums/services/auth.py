from ums import exceptions
from ums.models import schemas, tables
from ums.models.auth import BaseUser
from ums.models.schemas import User
from ums.repositories import UserRepo
from ums.roles.permission import Permission

from ums.security.filters import permission_filter
from ums.security.jwt import JwtTokenProcessor
from ums.security.session import SessionManager
from ums.security.utils import verify_password, get_hashed_password
from ums.utils import RedisClient


class AuthApplicationService:
    def __init__(
            self,
            current_user: BaseUser,
            *,
            jwt: JwtTokenProcessor,
            session_manager: SessionManager,
            user_repo: UserRepo,
            redis_client_reauth: RedisClient,
    ):
        self._current_user = current_user
        self.jwt = jwt
        self.session_manager = session_manager
        self.user_repo = user_repo
        self.redis_client_reauth = redis_client_reauth

    @permission_filter(Permission.CREATE_USER)
    async def create_user(self, user: schemas.UserCreate) -> None:
        """
        Создание нового пользователя

        :param user: UserCreate

        :raise AccessDenied if user is already logged in
        :raise AlreadyExists Conflict if user already exists

        :return: User
        """

        if await self.user_repo.get_by_email_insensitive(user.email):
            raise exceptions.AlreadyExists(f"Пользователь с email {user.email!r} уже существует")

        hashed_password = get_hashed_password(user.password)
        await self.user_repo.create(
            **user.model_dump(exclude={"password"}),
            role_id=0,
            hashed_password=hashed_password
        )

    @permission_filter(Permission.AUTHENTICATE)
    async def authenticate(self, data: schemas.UserAuth) -> tuple[User, tuple[str, str], str]:
        """
        Аутентификация пользователя

        :param data: UserAuth

        :return: User

        :raise AlreadyExists: if user is already logged in
        :raise NotFound: if user not found
        :raise AccessDenied: if user is banned
        """

        user: tables.User = await self.user_repo.get_by_email_insensitive(email=data.email, as_full=True)
        if not user:
            raise exceptions.NotFound("Пользователь не найден")
        if not verify_password(data.password, user.hashed_password):
            raise exceptions.NotFound("Неверная пара логин/пароль")
        if user.state == schemas.UserState.BLOCKED:
            raise exceptions.AccessDenied("Пользователь заблокирован")
        if user.state == schemas.UserState.NOT_CONFIRMED:
            raise exceptions.AccessDenied("Пользователь не подтвержден")
        if user.state == schemas.UserState.DELETED:
            raise exceptions.AccessDenied("Пользователь удален")

        # Генерация и установка токенов
        permission_title_list = [obj.title for obj in user.role.permissions]
        tokens = (
            self.jwt.create_token(user.id, permission_title_list, user.state, "access"),
            self.jwt.create_token(user.id, permission_title_list, user.state, "refresh")
        )
        session_id = await self.session_manager.set_session_id(
            refresh_token=tokens[1],
            user_id=user.id,
            ip_address=self._current_user.ip,
            user_agent=str(self._current_user.user_agent)
        )
        user_model = schemas.User.model_validate(user)
        return user_model, tokens, session_id

    @permission_filter(Permission.LOGOUT)
    async def logout(self, session_id: str | None) -> None:
        if session_id and self._current_user.id:
            await self.session_manager.delete_session(self._current_user.id, session_id)

    async def refresh_tokens(
            self,
            current_tokens: tuple[str | None, str | None],
            session_id: str | None
    ) -> tuple[schemas.User, tuple[str, str], str]:
        """
        Обновление токенов

        :param current_tokens: tuple[access_token, refresh_token]
        :param session_id:

        :raise AccessDenied if session is invalid or user is banned
        :raise NotFound if user not found

        :return:
        """

        if not self._current_user.is_valid_session:
            raise exceptions.AccessDenied("Сессия недействительна")

        if not self._current_user.is_valid_refresh_token:
            raise exceptions.AccessDenied("Недействительный refresh token")

        old_payload = self.jwt.validate_token(current_tokens[1])
        user = await self.user_repo.get(id=old_payload.id, as_full=True)
        if not user:
            raise exceptions.NotFound("Пользователь не найден")

        if user.state == schemas.UserState.BLOCKED:
            raise exceptions.AccessDenied("Пользователь заблокирован")

        permission_title_list = [obj.title for obj in user.role.permissions]
        new_tokens = (
            self.jwt.create_token(user.id, permission_title_list, user.state, "access"),
            self.jwt.create_token(user.id, permission_title_list, user.state, "refresh")
        )
        new_session_id = await self.session_manager.set_session_id(
            user_id=user.id,
            refresh_token=new_tokens[1],
            ip_address=self._current_user.ip,
            user_agent=str(self._current_user.user_agent),
            session_id=session_id
        )
        await self.redis_client_reauth.delete(session_id)
        user_model = schemas.User.model_validate(user)
        return (
            user_model,
            new_tokens,
            new_session_id
        )
