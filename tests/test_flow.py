from http import HTTPStatus
from typing import Any, Callable, Dict
from urllib.parse import parse_qsl, urlparse

import pytest

from aioauth.constances import default_headers
from aioauth.requests import Post, Query, Request
from aioauth.server import AuthorizationServer
from aioauth.storage import BaseStorage
from aioauth.types import GrantType, ResponseType
from aioauth.utils import (
    create_s256_code_challenge,
    encode_auth_headers,
    enforce_list,
    generate_token,
)

from tests.classes import BasicServerConfig, Storage
from tests.utils import check_request_validators


@pytest.mark.asyncio
@pytest.mark.override_defaults(client_secret="")
async def test_authorization_code_flow_plain_code_challenge(
    db: BaseStorage,
    defaults: BasicServerConfig,
    default_server_factory: Callable[
        [Dict[GrantType, Any], Dict[ResponseType, Any], Storage], AuthorizationServer
    ],
):
    server = default_server_factory()
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    scope = defaults.scope
    redirect_uri = defaults.redirect_uri
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=client_id,
        code_challenge=code_challenge,
        code_challenge_method="plain",
        redirect_uri=redirect_uri,
        response_type="code",
        scope=scope,
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)
    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    assert query["scope"] == scope
    assert await db.get_authorization_code(request, client_id, query["code"])
    assert "code" in query

    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]

    post = Post(
        client_id=client_id,
        code=code,
        code_verifier=code_challenge,
        grant_type="authorization_code",
        redirect_uri=defaults.redirect_uri,
        scope=scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
    assert response.headers == default_headers
    assert response.content["scope"] == scope
    assert response.content["token_type"] == "Bearer"
    # Check that token was created in db
    assert await db.get_token(
        request=request,
        client_id=client_id,
        access_token=response.content["access_token"],
        refresh_token=response.content["refresh_token"],
    )

    access_token = response.content["access_token"]
    refresh_token = response.content["refresh_token"]

    post = Post(
        client_id=client_id,
        grant_type="refresh_token",
        refresh_token=refresh_token,
        scope=scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )
    await check_request_validators(request, server.create_token_response)
    response = await server.create_token_response(request)

    assert response.status_code == HTTPStatus.OK
    assert response.content["access_token"] != access_token
    assert response.content["refresh_token"] != refresh_token
    # Check that token was created in db
    assert await db.get_token(
        request=request,
        client_id=client_id,
        access_token=response.content["access_token"],
        refresh_token=response.content["refresh_token"],
    )
    # Check that previous token was revoken
    token_in_db = await db.get_token(
        request=request,
        client_id=client_id,
        access_token=access_token,
        refresh_token=refresh_token,
    )
    assert token_in_db.revoked  # type: ignore

    # check that scope is previous scope
    new_token = await db.get_token(
        request=request,
        client_id=client_id,
        access_token=response.content["access_token"],
        refresh_token=response.content["refresh_token"],
    )
    assert set(enforce_list(new_token.scope)) == set(enforce_list(token_in_db.scope))  # type: ignore


@pytest.mark.asyncio
@pytest.mark.override_defaults(client_secret="")
async def test_authorization_code_flow_pkce_code_challenge(
    server: AuthorizationServer, defaults: BasicServerConfig, db: BaseStorage
):
    client_id = defaults.client_id
    code_verifier = generate_token(128)
    scope = defaults.scope
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"
    user = "username"
    state = generate_token(10)

    query = Query(
        client_id=defaults.client_id,
        response_type="code",
        redirect_uri=defaults.redirect_uri,
        scope=scope,
        state=state,
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
    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    assert query["state"] == state
    assert query["scope"] == scope
    assert "code" in query
    code = query["code"]

    post = Post(
        client_id=client_id,
        code=code,
        code_verifier=code_verifier,
        grant_type="authorization_code",
        redirect_uri=defaults.redirect_uri,
        scope=scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )

    await check_request_validators(request, server.create_token_response)

    code_record = await db.get_authorization_code(request, client_id, code)
    assert code_record

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
    assert response.headers == default_headers
    assert response.content["scope"] == scope
    assert response.content["token_type"] == "Bearer"

    code_record = await db.get_authorization_code(request, client_id, code)
    assert not code_record


@pytest.mark.asyncio
async def test_implicit_flow(server: AuthorizationServer, defaults: BasicServerConfig):
    request_url = "https://localhost"
    state = generate_token(10)
    scope = defaults.scope
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type="token",
        redirect_uri=defaults.redirect_uri,
        scope=scope,
        state=state,
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))
    assert fragment["state"] == state
    assert fragment["scope"] == scope


@pytest.mark.asyncio
async def test_password_grant_type_with_client_secret(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
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
        headers=encode_auth_headers(client_id, client_secret),
    )

    await check_request_validators(request, server.create_token_response)
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
@pytest.mark.override_defaults(client_secret="")
async def test_password_grant_type_without_client_secret(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    client_id = defaults.client_id
    request_url = "https://localhost"

    post = Post(
        client_id=client_id,
        grant_type="password",
        username=defaults.username,
        password=defaults.password,
    )

    request = Request(
        post=post,
        url=request_url,
        method="POST",
    )

    await check_request_validators(request, server.create_token_response)
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
@pytest.mark.override_defaults(client_secret="")
async def test_password_grant_type_without_client_secret_using_basic_auth(
    server: AuthorizationServer, defaults: BasicServerConfig
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
        headers=encode_auth_headers(client_id, ""),
    )

    await check_request_validators(request, server.create_token_response)
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
@pytest.mark.override_defaults(client_secret="")
async def test_authorization_code_flow(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    client_id = defaults.client_id
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type="code",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND

    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]

    post = Post(
        client_id=client_id,
        code=code,
        grant_type="authorization_code",
        redirect_uri=defaults.redirect_uri,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
@pytest.mark.override_defaults(client_secret="")
async def test_authorization_code_flow_credentials_in_post(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    client_id = defaults.client_id
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type="code",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND

    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]

    post = Post(
        grant_type="authorization_code",
        client_id=client_id,
        redirect_uri=defaults.redirect_uri,
        code=code,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_client_credentials_flow_post_data(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    request_url = "https://localhost"

    post = Post(
        client_id=defaults.client_id,
        client_secret=defaults.client_secret,
        grant_type="client_credentials",
        scope=defaults.scope,
    )

    request = Request(url=request_url, post=post, method="POST")

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_client_credentials_flow_auth_header(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    request_url = "https://localhost"

    post = Post(
        grant_type="client_credentials",
        scope=defaults.scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
        headers=encode_auth_headers(
            client_id=defaults.client_id, client_secret=defaults.client_secret
        ),
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_multiple_response_types(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type="code token",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))

    assert "state" in fragment
    assert "expires_in" in fragment
    assert "refresh_token_expires_in" in fragment
    assert "access_token" in fragment
    assert "refresh_token" in fragment
    assert "scope" in fragment
    assert "token_type" in fragment
    assert "code" in fragment


@pytest.mark.asyncio
async def test_response_type_none(
    server: AuthorizationServer, defaults: BasicServerConfig
):
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type="none",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))
    query = dict(parse_qsl(location.query))
    assert fragment == {}
    assert query == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response_mode,",
    [
        "query",
        "form_post",
        "fragment",
        None,
    ],
)
async def test_response_type_id_token(
    server: AuthorizationServer, defaults: BasicServerConfig, response_mode
):
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type="code token id_token",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        nonce="123",
        response_mode=response_mode,
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)

    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))
    query = dict(parse_qsl(location.query))

    if response_mode == "fragment":
        assert "state" in fragment
        assert "expires_in" in fragment
        assert "refresh_token_expires_in" in fragment
        assert "access_token" in fragment
        assert "refresh_token" in fragment
        assert "scope" in fragment
        assert "token_type" in fragment
        assert "code" in fragment
        assert "id_token" in fragment
    elif response_mode == "form_post":
        assert "state" in response.content
        assert "expires_in" in response.content
        assert "refresh_token_expires_in" in response.content
        assert "access_token" in response.content
        assert "refresh_token" in response.content
        assert "scope" in response.content
        assert "token_type" in response.content
        assert "code" in response.content
        assert "id_token" in response.content
    elif response_mode == "query":
        assert "state" in query
        assert "expires_in" in query
        assert "refresh_token_expires_in" in query
        assert "access_token" in query
        assert "refresh_token" in query
        assert "scope" in query
        assert "token_type" in query
        assert "code" in query
        assert "id_token" in query
    else:
        assert "state" in fragment
        assert "expires_in" in fragment
        assert "refresh_token_expires_in" in fragment
        assert "access_token" in fragment
        assert "refresh_token" in fragment
        assert "scope" in fragment
        assert "token_type" in fragment
        assert "code" in fragment
        assert "id_token" in fragment
