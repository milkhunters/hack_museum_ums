from fastapi import Depends
from fastapi.requests import Request

from ums.dependencies.repos import get_repos
from ums.services import ServiceFactory
from ums.repositories import RepoFactory


async def get_services(request: Request, repos: RepoFactory = Depends(get_repos)) -> ServiceFactory:
    global_scope = request.app.state
    local_scope = request.scope

    yield ServiceFactory(
        repos,
        current_user=local_scope.get("user"),
        redis_reauth=global_scope.redis_reauth,
        session_manager=global_scope.session_manager,
        config=global_scope.config,
        jwt=global_scope.jwt,
        lazy_session=global_scope.db_session
    )
