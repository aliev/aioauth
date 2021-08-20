from aioauth.config import Settings
import pytest
from aioauth.server import AuthorizationServer
from fastapi import FastAPI
from async_asgi_testclient import TestClient
from aioauth.fastapi.router import get_oauth2_router
from http import HTTPStatus
from starlette.authentication import (
    AuthenticationBackend,
    SimpleUser,
    UnauthenticatedUser,
    AuthCredentials,
)
from starlette.middleware.authentication import AuthenticationMiddleware


class CookiesAuthenticationBackend(AuthenticationBackend):
    async def authenticate(self, request):
        token: str = request.cookies.get("token")

        if token:
            return AuthCredentials(), SimpleUser(username="admin")
        return AuthCredentials(), UnauthenticatedUser()


@pytest.fixture
def app(server: AuthorizationServer, settings: Settings):
    app = FastAPI()
    app.add_middleware(AuthenticationMiddleware, backend=CookiesAuthenticationBackend())
    app.include_router(get_oauth2_router(server, settings=settings))
    return app


@pytest.mark.asyncio
async def test_responses(app):
    async with TestClient(app) as ac:
        response = await ac.get("/authorize", cookies={"token": "user"})
        assert response.status_code == HTTPStatus.BAD_REQUEST

        response = await ac.post("/token")
        assert response.status_code == HTTPStatus.BAD_REQUEST

        response = await ac.post("/token/introspect")
        assert response.status_code == HTTPStatus.UNAUTHORIZED
