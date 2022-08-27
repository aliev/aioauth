import time
from http import HTTPStatus
from typing import Dict, List, Optional, Type

import pytest

from aioauth.config import Settings
from aioauth.models import Token
from aioauth.requests import Post, Request
from aioauth.server import AuthorizationServer
from aioauth.utils import (
    catch_errors_and_unavailability,
    encode_auth_headers,
    generate_token,
)

from .classes import Storage
from .models import Defaults


@pytest.mark.asyncio
async def test_internal_server_error():
    class EndpointClass:
        available: Optional[bool] = True

        def __init__(self, available: Optional[bool] = None):
            if available is not None:
                self.available = available

        @catch_errors_and_unavailability
        async def server(self, request):
            raise Exception()

    e = EndpointClass()
    response = await e.server(Request(method="POST"))
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_invalid_token(server: AuthorizationServer, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"
    token = "invalid token"

    post = Post(token=token)
    request = Request(
        url=request_url,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )
    response = await server.create_token_introspection_response(request)
    assert not response.content["active"]
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_expired_token(
    server: AuthorizationServer, storage: Dict[str, List], defaults: Defaults
):
    settings = Settings(INSECURE_TRANSPORT=True)
    token = Token(
        client_id=defaults.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
        refresh_token_expires_in=settings.REFRESH_TOKEN_EXPIRES_IN,
        access_token=generate_token(42),
        refresh_token=generate_token(48),
        issued_at=int(time.time() - settings.TOKEN_EXPIRES_IN),
        scope=defaults.scope,
    )

    client_id = defaults.client_id
    client_secret = defaults.client_secret

    storage["tokens"].append(token)

    post = Post(token=token.access_token)
    request = Request(
        settings=settings,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.OK
    assert not response.content["active"]


@pytest.mark.asyncio
async def test_valid_token(
    server: AuthorizationServer,
    storage: Dict[str, List],
    defaults: Defaults,
    settings: Settings,
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    token = storage["tokens"][0]

    post = Post(token=token.refresh_token)
    request = Request(
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
        settings=settings,
    )

    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.OK
    assert response.content["active"]


@pytest.mark.asyncio
async def test_introspect_revoked_token(
    server: AuthorizationServer,
    storage: Dict[str, List],
    defaults: Defaults,
    settings: Settings,
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    token = storage["tokens"][0]

    post = Post(
        grant_type="refresh_token",
        refresh_token=token.refresh_token,
    )
    request = Request(
        settings=settings,
        url=request_url,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK

    # Check that refreshed token was revoked
    post = Post(token=token.access_token, token_type_hint="access_token")
    request = Request(
        settings=settings,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )
    response = await server.create_token_introspection_response(request)
    assert not response.content["active"], "The refresh_token must be revoked"


@pytest.mark.asyncio
async def test_endpoint_availability(db_class: Type[Storage]):
    server = AuthorizationServer[Request, Storage](storage=db_class())
    request = Request(method="POST", settings=Settings(AVAILABLE=False))
    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content["error"] == "temporarily_unavailable"
