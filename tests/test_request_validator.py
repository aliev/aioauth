import time
from http import HTTPStatus
from urllib.parse import urlparse, parse_qs

import pytest

from aioauth.requests import Post, Query, Request
from aioauth.server import AuthorizationServer
from aioauth.utils import (
    create_s256_code_challenge,
    encode_auth_headers,
    generate_token,
)

from tests import factories
from tests.classes import AuthorizationContext


@pytest.mark.asyncio
async def test_insecure_transport_error(server: AuthorizationServer):
    request_url = "http://localhost"

    request = Request(url=request_url, method="GET")

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    query_params = parse_qs(urlparse(response.headers["Location"]).query)
    assert query_params["error"] == ["insecure_transport"]


@pytest.mark.asyncio
async def test_allowed_methods(server: AuthorizationServer):
    request_url = "https://localhost"

    request = Request(url=request_url, method="DELETE")  # type: ignore

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED


@pytest.mark.asyncio
async def test_invalid_client_credentials(context_factory):
    username = "username"
    password = "password"
    context = context_factory(users={username: password})
    server = context.server
    client = context.clients[0]
    client_id = client.client_id
    request_url = "https://localhost"

    post = Post(
        grant_type="password",
        username=username,
        password=password,
    )

    request = Request(
        post=post,
        url=request_url,
        method="POST",
        headers=encode_auth_headers(client_id, "client_secret"),
    )

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.content["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_invalid_scope(context_factory):
    username = "username"
    password = "password"
    context = context_factory(users={username: password})
    client = context.clients[0]
    server = context.server
    client_id = client.client_id
    client_secret = client.client_secret
    request_url = "https://localhost"

    post = Post(
        grant_type="password",
        username=username,
        password=password,
        scope="bad scope here",
    )

    request = Request(
        post=post,
        url=request_url,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_invalid_grant_type():
    client = factories.client_factory(grant_types=["authorization_code"])
    username = "username"
    password = "password"
    context = factories.context_factory(
        clients=[client],
        users={username: password},
    )
    server = context.server

    request_url = "https://localhost"

    post = Post(
        grant_type="password",
        username=username,
        password=password,
        scope=client.scope,
    )

    request = Request(
        post=post,
        url=request_url,
        method="POST",
        headers=encode_auth_headers(client.client_id, client.client_secret),
    )

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content["error"] == "unauthorized_client"


@pytest.mark.asyncio
async def test_invalid_response_type():
    client = factories.client_factory(response_types=["token"])
    username = "username"
    context = factories.context_factory(
        clients=[client],
        users={username: "password"},
    )
    server = context.server

    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"

    query = Query(
        client_id=client.client_id,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        scope=client.scope,
        state=generate_token(10),
        code_challenge_method="S256",
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
    )
    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    query_params = parse_qs(urlparse(response.headers["Location"]).query)
    assert query_params["error"] == ["unsupported_response_type"]


@pytest.mark.asyncio
async def test_anonymous_user(context: AuthorizationContext):
    client = context.clients[0]
    server = context.server
    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"

    query = Query(
        client_id=client.client_id,
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        scope=client.scope,
        state=generate_token(10),
        code_challenge_method="S256",
        code_challenge=code_challenge,
    )

    request = Request(url=request_url, query=query, method="GET")
    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND


@pytest.mark.asyncio
async def test_expired_authorization_code():
    settings = factories.settings_factory()
    client = factories.client_factory(client_secret="")
    authorization_code = factories.authorization_code_factory(
        auth_time=(int(time.time()) - settings.AUTHORIZATION_CODE_EXPIRES_IN),
    )
    context = factories.context_factory(
        clients=[client],
        initial_authorization_codes=[authorization_code],
    )
    server = context.server

    request_url = "https://localhost"

    post = Post(
        client_id=client.client_id,
        code=authorization_code.code,
        grant_type="authorization_code",
        redirect_uri=client.redirect_uris[0],
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_expired_refresh_token():
    settings = factories.settings_factory()
    client = factories.client_factory(client_secret="")
    token = factories.token_factory(
        issued_at=(int(time.time()) - (settings.TOKEN_EXPIRES_IN * 2))
    )
    refresh_token = token.refresh_token
    context = factories.context_factory(
        clients=[client],
        initial_tokens=[token],
    )
    server = context.server
    request_url = "https://localhost"
    post = Post(
        client_id=client.client_id,
        grant_type="refresh_token",
        refresh_token=refresh_token,
    )
    request = Request(
        url=request_url,
        post=post,
        method="POST",
        settings=settings,
    )
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content["error"] == "invalid_grant"
