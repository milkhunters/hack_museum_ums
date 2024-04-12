import asyncio
import logging
from typing import Callable, AsyncGenerator

import redis.asyncio as redis
from fastapi import FastAPI
from grpc import aio

from ums.config import Config, RedisConfig
from ums.db import create_psql_async_session
from ums.models.schemas.role import RoleID
from ums.protos.ums_control import ums_control_pb2_grpc
from ums.repositories import RoleRepo, PermissionRepo
from ums.roles import RoleLoader
from ums.services import SessionManager
from ums.services.ums_control import UMService
from ums.utils import RedisClient


async def init_db(app: FastAPI, config: Config):
    engine, session = create_psql_async_session(
        host=config.DB.POSTGRESQL.HOST,
        port=config.DB.POSTGRESQL.PORT,
        username=config.DB.POSTGRESQL.USERNAME,
        password=config.DB.POSTGRESQL.PASSWORD,
        database=config.DB.POSTGRESQL.DATABASE,
        echo=config.DEBUG,
    )
    getattr(app, "state").db_session = session


async def init_sessions(app: FastAPI, config: RedisConfig):
    client = await redis.from_url(
        f"redis://:{config.PASSWORD}@{config.HOST}:{config.PORT}/0",
        encoding="utf-8",
        decode_responses=True,
    )
    getattr(app, "state").session_manager = SessionManager(
        redis_client=RedisClient(client)
    )


async def init_redis_pool(app: FastAPI, config: Config):
    pool_1 = await redis.from_url(
        f"redis://:{config.DB.REDIS.PASSWORD}@{config.DB.REDIS.HOST}:{config.DB.REDIS.PORT}/1",
        encoding="utf-8",
        decode_responses=True,
    )
    getattr(app, "state").redis_reauth = RedisClient(pool_1)


async def init_roles(db_session: Callable[[], AsyncGenerator], models_path: str) -> None:
    logging.debug("Инициализация ролей.")

    roles = RoleLoader(models_path).roles

    default_id = 0
    default_role_model = next((role for role in roles if role.id == default_id), None)

    if not default_role_model:
        raise FileNotFoundError(f"Файл роли по умолчанию с default_id:{default_id} не найден.")

    async with db_session() as session:
        role_repo = RoleRepo(session)
        permission_repo = PermissionRepo(session)

        for _ in roles:
            role = await role_repo.get(id=_.id, as_full=True)
            if not role:
                await role_repo.create(id=_.id, title=_.title)
                await session.commit()

                for permission_tag in _.permissions:
                    permission = await permission_repo.get(title=permission_tag)
                    if not permission:
                        permission = await permission_repo.create(title=permission_tag)
                        await session.commit()

                    await role_repo.add_link(role_id=RoleID(_.id), permission_id=permission.id)
                    await session.commit()


async def grpc_server(redis_reauth, host: str, port: int):
    server = aio.server()
    ums_control_pb2_grpc.add_UserManagementServicer_to_server(UMService(redis_reauth), server)
    listen_addr = f"{host}:{port}"
    server.add_insecure_port(listen_addr)
    logging.info(f"Starting gRPC server on {listen_addr}", )
    await server.start()
    await server.wait_for_termination()


class LifeSpan:

    def __init__(self, app: FastAPI, config: Config):
        self.app = app
        self.config = config

    async def startup_handler(self) -> None:
        logging.debug("Выполнение FastAPI startup event handler.")
        await init_db(self.app, self.config)
        await init_redis_pool(self.app, self.config)
        await init_sessions(self.app, self.config.DB.REDIS)
        await init_roles(getattr(self.app, "state").db_session, "src/ums/roles/models/")
        asyncio.get_running_loop().create_task(
            grpc_server(
                getattr(self.app, "state").redis_reauth,
                host="localhost",
                port=50051
            )
        )
        logging.info("FastAPI Успешно запущен.")

    async def shutdown_handler(self) -> None:
        logging.debug("Выполнение FastAPI shutdown event handler.")
        await getattr(self.app, "state").redis_sessions.close()
        await getattr(self.app, "state").redis_reauth.close()
