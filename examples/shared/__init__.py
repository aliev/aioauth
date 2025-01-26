"""
Shared Utilites and Implementation for AioAuth Storage Interfaces
"""

from contextlib import asynccontextmanager

import os
from typing import Optional
from aioauth.server import AuthorizationServer

from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from .config import load_config
from .storage import BackendStore
from .models import User

__all__ = [
    "AuthServer",
    "BackendStore",
    "engine",
    "app_config",
    "settings",
    "try_login",
    "lifespan",
]

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config.json")

engine: AsyncEngine = create_async_engine(
    "sqlite+aiosqlite:///:memory:", echo=False, future=True
)

app_config = load_config(CONFIG_PATH)
settings = app_config.settings


async def try_login(username: str, password: str) -> Optional[User]:
    """
    try username and password against user fixtures in database
    """
    async with AsyncSession(engine) as conn:
        sql = select(User).where(
            User.username == username and User.password == password
        )
        record = await conn.exec(sql)
        return record.first()


@asynccontextmanager
async def lifespan(*_):
    """
    async database startup/shutdown context-manager
    """
    global oauth
    # spawn connection pool and ensure tables are made
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    # create test records
    async with AsyncSession(engine) as session:
        for user in app_config.fixtures.users:
            session.add(user)
        for client in app_config.fixtures.clients:
            session.add(client)
        await session.commit()
    yield
    # close connections on app closure
    await engine.dispose()


class AuthServer(AuthorizationServer):
    pass
