from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from ums.models import tables
from ums.repositories.base import BaseRepository


class UserRepo(BaseRepository[tables.User]):
    table = tables.User

    async def get(self, as_full: bool = False, **kwargs) -> tables.User | None:
        req = select(self.table).filter_by(**kwargs)
        if as_full:
            req = req.options(joinedload(self.table.role).subqueryload(tables.Role.permissions))
        return (await self._session.execute(req)).scalars().first()

    async def get_by_email_insensitive(self, email: str, as_full: bool = False) -> tables.User | None:
        req = select(self.table).where(func.lower(self.table.email) == email.lower())
        if as_full:
            req = req.options(joinedload(self.table.role).subqueryload(tables.Role.permissions))
        return (await self._session.execute(req)).scalar_one_or_none()