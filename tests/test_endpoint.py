import time
from http import HTTPStatus
from typing import Dict, List, Optional, Type

import pytest
from aioauth.base.database import BaseDB
from aioauth.config import Settings
from aioauth.models import Token
from aioauth.requests import Post, Request
from aioauth.server import AuthorizationServer
from aioauth.types import EndpointType, ErrorType, GrantType, RequestMethod
from aioauth.utils import (
    catch_errors_and_unavailability,
    encode_auth_headers,
    generate_token,
)

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
    response = await e.server(Request(method=RequestMethod.POST))
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
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )
    response = await server.create_token_introspection_response(request)
    assert not response.content.active
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_expired_token(
    server: AuthorizationServer, storage: Dict[str, List], defaults: Defaults
):
    settings = Settings()
    token = Token(
        client_id=defaults.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
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
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.OK
    assert not response.content.active


@pytest.mark.asyncio
async def test_valid_token(
    server: AuthorizationServer, storage: Dict[str, List], defaults: Defaults
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    token = storage["tokens"][0]

    post = Post(token=token.access_token)
    request = Request(
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.OK
    assert response.content.active


@pytest.mark.asyncio
async def test_unregister_endpoint(server: AuthorizationServer):
    assert server.grant_type.get(GrantType.TYPE_AUTHORIZATION_CODE) is not None
    server.unregister(EndpointType.GRANT_TYPE, GrantType.TYPE_AUTHORIZATION_CODE)
    assert server.grant_type.get(GrantType.TYPE_AUTHORIZATION_CODE) is None


@pytest.mark.asyncio
async def test_endpoint_availability(db_class: Type[BaseDB]):
    server = AuthorizationServer(db=db_class())
    request = Request(method=RequestMethod.POST, settings=Settings(AVAILABLE=False))
    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.TEMPORARILY_UNAVAILABLE
