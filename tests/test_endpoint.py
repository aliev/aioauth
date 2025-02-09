import time
from http import HTTPStatus
from typing import Optional

import pytest

from aioauth.config import Settings
from aioauth.requests import Post, Request
from aioauth.utils import (
    catch_errors_and_unavailability,
    encode_auth_headers,
)

from tests import factories
from tests.classes import AuthorizationContext


@pytest.mark.asyncio
async def test_internal_server_error() -> None:
    class EndpointClass:
        available: Optional[bool] = True

        def __init__(self, available: Optional[bool] = None):
            if available is not None:
                self.available = available

        @catch_errors_and_unavailability()
        async def server(self, request):
            raise Exception()

    e = EndpointClass()
    response = await e.server(Request(method="POST"))
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_invalid_token(context: AuthorizationContext):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret
    server = context.server
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
async def test_expired_token(context_factory):
    settings = factories.settings_factory()
    client = factories.client_factory()
    token = factories.token_factory(
        client_id=client.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
        refresh_token_expires_in=settings.REFRESH_TOKEN_EXPIRES_IN,
        issued_at=int(time.time() - settings.TOKEN_EXPIRES_IN),
        scope=client.scope,
    )
    context = context_factory(
        clients=[client],
        initial_tokens=[token],
        settings=settings,
    )
    server = context.server

    client_id = client.client_id
    client_secret = client.client_secret

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
async def test_valid_token(context: AuthorizationContext):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret

    settings = context.settings
    token = context.initial_tokens[0]
    server = context.server

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
async def test_introspect_revoked_token(context: AuthorizationContext):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret
    request_url = "https://localhost"

    token = context.initial_tokens[0]
    settings = context.settings
    server = context.server

    post = Post(
        client_id=client_id,
        client_secret=client_secret,
        grant_type="refresh_token",
        refresh_token=token.refresh_token,
    )
    request = Request(
        settings=settings,
        url=request_url,
        post=post,
        method="POST",
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
async def test_endpoint_availability(context_factory):
    settings = Settings(AVAILABLE=False)
    context = context_factory(settings=settings)
    server = context.server
    request = Request(method="POST", settings=settings)
    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content["error"] == "temporarily_unavailable"


@pytest.mark.asyncio
async def test_introspect_token_with_wrong_client_secret(context: AuthorizationContext):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret

    settings = context.settings
    token = context.initial_tokens[0]
    server = context.server

    post = Post(token=token.refresh_token)
    request = Request(
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, f"not {client_secret}"),
        settings=settings,
    )

    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.content["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_introspect_token_without_client_secret():
    client = factories.client_factory(client_secret="")
    context = factories.context_factory(clients=[client])
    client_id = client.client_id

    settings = context.settings
    token = context.initial_tokens[0]
    server = context.server

    post = Post(token=token.refresh_token, client_id=client_id)
    request = Request(
        post=post,
        method="POST",
        settings=settings,
    )

    response = await server.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.content["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_revoke_refresh_token(context: AuthorizationContext):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret

    settings = context.settings
    token = context.initial_tokens[0]
    server = context.server

    post = Post(token=token.refresh_token, token_type_hint="refresh_token")
    request = Request(
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
        settings=settings,
    )

    response = await server.revoke_token(request)
    assert response.status_code == HTTPStatus.NO_CONTENT

    # Check that the token was revoked
    request = Request(
        settings=settings,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )
    response = await server.create_token_introspection_response(request)
    assert not response.content["active"], "The refresh_token must be revoked"


@pytest.mark.asyncio
async def test_revoke_access_token(context: AuthorizationContext):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret

    settings = context.settings
    token = context.initial_tokens[0]
    server = context.server

    post = Post(token=token.access_token, token_type_hint="access_token")
    request = Request(
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
        settings=settings,
    )

    response = await server.revoke_token(request)
    assert response.status_code == HTTPStatus.NO_CONTENT

    # Check that the token was revoked
    request = Request(
        settings=settings,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )
    response = await server.create_token_introspection_response(request)
    assert not response.content["active"], "The access_token must be revoked"


@pytest.mark.asyncio
async def test_revoke_access_token_without_client_secret():
    client = factories.client_factory(client_secret="")
    context = factories.context_factory(clients=[client])
    client_id = client.client_id

    settings = context.settings
    token = context.initial_tokens[0]
    server = context.server

    post = Post(
        token=token.access_token,
        token_type_hint="access_token",
        client_id=client_id,
    )
    request = Request(
        post=post,
        method="POST",
        settings=settings,
    )

    response = await server.revoke_token(request)
    assert response.status_code == HTTPStatus.NO_CONTENT


@pytest.mark.asyncio
async def test_revoke_access_token_with_wrong_client_secret(
    context: AuthorizationContext,
):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret

    settings = context.settings
    token = context.initial_tokens[0]
    server = context.server

    post = Post(token=token.access_token, token_type_hint="access_token")
    request = Request(
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, f"not {client_secret}"),
        settings=settings,
    )

    response = await server.revoke_token(request)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.content["error"] == "invalid_client"
