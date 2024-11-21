"""
Utilis and Implementation for AioAuth Storage Interfaces
"""
from contextlib import asynccontextmanager

from aioauth.server import AuthorizationServer

from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from .models import Client
from .storage import BackendStore, User

#** Variables **#
__all__ = ['AuthServer', 'BackendStore', 'engine', 'auto_login', 'lifespan']

engine: AsyncEngine = create_async_engine('sqlite+aiosqlite:///:memory:', echo=False, future=True)

async def auto_login() -> User:
    """
    return test user-account simulating login
    """
    async with AsyncSession(engine) as conn:
        sql = select(User).where(User.username == 'test')
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
            username='test',
            password='password',
        )
        client = Client(
            client_id='test_client',
            client_secret='password',
            grant_types='authorization_code,refresh_token',
            redirect_uris='http://localhost:3000/redirect',
            response_types='code',
            scope='email'
        )
        session.add(user)
        session.add(client)
        await session.commit()
    yield
    # close connections on app closure
    await engine.dispose()

class AuthServer(AuthorizationServer[User]):
    pass
