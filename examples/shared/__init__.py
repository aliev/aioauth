"""
Shared Utilites and Implementation for AioAuth Storage Interfaces
"""

from contextlib import asynccontextmanager

import os
from aioauth.server import AuthorizationServer

from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from .config import load_config
from .models import Client
from .storage import BackendStore, User

__all__ = [
    "AuthServer",
    "BackendStore",
    "engine",
    "config",
    "settings",
    "auto_login",
    "lifespan",
]

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config.json")

engine: AsyncEngine = create_async_engine(
    "sqlite+aiosqlite:///:memory:", echo=False, future=True
)

config = load_config(CONFIG_PATH)
settings = config.settings


async def auto_login() -> User:
    """
    return test user-account simulating login
    """
    async with AsyncSession(engine) as conn:
        sql = select(User).where(User.username == "test")
        return (await conn.exec(sql)).one()


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
        user = User(
            username="test",
            password="password",
        )
        client = Client(
            client_id="test_client",
            client_secret="password",
            grant_types="authorization_code,refresh_token",
            redirect_uris="http://localhost:3000/redirect",
            response_types="code",
            scope="email",
        )
        session.add(user)
        session.add(client)
        await session.commit()
    yield
    # close connections on app closure
    await engine.dispose()


class AuthServer(AuthorizationServer[User]):
    pass
