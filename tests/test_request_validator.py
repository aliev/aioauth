import time
from dataclasses import replace
from http import HTTPStatus
from typing import Dict, List
from urllib.parse import urlparse, parse_qs

import pytest

from aioauth.config import Settings
from aioauth.models import Client
from aioauth.requests import Post, Query, Request
from aioauth.server import AuthorizationServer
from aioauth.utils import (
    create_s256_code_challenge,
    encode_auth_headers,
    generate_token,
)

from .models import Defaults


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
async def test_invalid_client_credentials(
    server: AuthorizationServer, defaults: Defaults
):
    client_id = defaults.client_id
    request_url = "https://localhost"

    post = Post(
        grant_type="password",
        username=defaults.username,
        password=defaults.password,
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
async def test_invalid_scope(server: AuthorizationServer, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(
        grant_type="password",
        username=defaults.username,
        password=defaults.password,
        scope="test test",
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
async def test_invalid_grant_type(
    server: AuthorizationServer, defaults: Defaults, storage
):
    client: Client = storage["clients"][0]

    client = replace(client, grant_types=["authorization_code"])

    storage["clients"][0] = client

    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(
        grant_type="password",
        username=defaults.username,
        password=defaults.password,
        scope="test test",
    )

    request = Request(
        post=post,
        url=request_url,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content["error"] == "unauthorized_client"


@pytest.mark.asyncio
async def test_invalid_response_type(
    server: AuthorizationServer, defaults: Defaults, storage
):
    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"
    user = "username"

    client = storage["clients"][0]

    client = replace(client, response_types=["token"])

    storage["clients"][0] = client

    query = Query(
        client_id=defaults.client_id,
        response_type="code",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method="S256",
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )
    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    query_params = parse_qs(urlparse(response.headers["Location"]).query)
    assert query_params["error"] == ["unsupported_response_type"]


@pytest.mark.asyncio
async def test_anonymous_user(server: AuthorizationServer, defaults: Defaults, storage):
    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"

    query = Query(
        client_id=defaults.client_id,
        response_type="code",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method="S256",
        code_challenge=code_challenge,
    )

    request = Request(url=request_url, query=query, method="GET")
    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.content["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_expired_authorization_code(
    server: AuthorizationServer,
    defaults: Defaults,
    storage: Dict[str, List],
    settings: Settings,
):
    request_url = "https://localhost"

    authorization_code = storage["authorization_codes"][0]
    storage["authorization_codes"][0] = replace(
        authorization_code,
        auth_time=(time.time() - settings.AUTHORIZATION_CODE_EXPIRES_IN),
    )
    post = Post(
        client_id=defaults.client_id,
        code=storage["authorization_codes"][0].code,
        grant_type="authorization_code",
        redirect_uri=defaults.redirect_uri,
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
async def test_expired_refresh_token(
    server: AuthorizationServer,
    defaults: Defaults,
    storage: Dict[str, List],
    settings: Settings,
):
    token = storage["tokens"][0]
    refresh_token = token.refresh_token
    storage["tokens"][0] = replace(
        token, issued_at=(time.time() - (settings.TOKEN_EXPIRES_IN * 2))
    )
    request_url = "https://localhost"
    post = Post(
        client_id=defaults.client_id,
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
