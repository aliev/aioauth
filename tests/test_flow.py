from http import HTTPStatus
from urllib.parse import parse_qsl, urlparse

import pytest

from aioauth.config import Settings
from aioauth.constances import default_headers
from aioauth.requests import Post, Query, Request
from aioauth.utils import (
    create_s256_code_challenge,
    encode_auth_headers,
    enforce_list,
    generate_token,
)

from tests import factories
from tests.classes import AuthorizationContext
from tests.utils import check_request_validators


@pytest.mark.asyncio
async def test_authorization_code_flow_plain_code_challenge():
    client = factories.client_factory(client_secret="")
    client_id = client.client_id
    redirect_uri = client.redirect_uris[0]

    code_challenge = generate_token(128)
    scope = client.scope
    username = "username"
    context = factories.context_factory(
        clients=[client],
        users={username: "password"},
    )
    server = context.server
    db = context.storage

    request_url = "https://localhost"
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
    )

    await check_request_validators(request, server.create_authorization_response)
    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    assert query["scope"] == scope
    assert await db.get_authorization_code(
        request=request, client_id=client_id, code=query["code"]
    )
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
        redirect_uri=redirect_uri,
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
        token_type="Bearer",
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
        token_type="access_token",
    )
    # Check that previous token was revoken
    token_in_db = await db.get_token(
        request=request,
        client_id=client_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="access_token",
    )
    assert token_in_db.revoked  # type: ignore

    # check that scope is previous scope
    new_token = await db.get_token(
        request=request,
        client_id=client_id,
        access_token=response.content["access_token"],
        refresh_token=response.content["refresh_token"],
        token_type="access_token",
    )
    assert set(enforce_list(new_token.scope)) == set(enforce_list(token_in_db.scope))  # type: ignore


@pytest.mark.asyncio
async def test_authorization_code_flow_pkce_code_challenge():
    client = factories.client_factory(client_secret="")
    context = factories.context_factory(clients=[client])
    server = context.server
    db = context.storage

    client_id = client.client_id
    code_verifier = generate_token(128)
    scope = client.scope
    code_challenge = create_s256_code_challenge(code_verifier)
    redirect_uri = client.redirect_uris[0]
    request_url = "https://localhost"
    state = generate_token(10)

    query = Query(
        client_id=client_id,
        response_type="code",
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
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
        redirect_uri=redirect_uri,
        scope=scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )

    await check_request_validators(request, server.create_token_response)

    code_record = await db.get_authorization_code(
        request=request, client_id=client_id, code=code
    )
    assert code_record

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
    assert response.headers == default_headers
    assert response.content["scope"] == scope
    assert response.content["token_type"] == "Bearer"

    code_record = await db.get_authorization_code(
        request=request, client_id=client_id, code=code
    )
    assert not code_record


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ids=["default_settings", "no_issue_refresh_token_implicit"],
    argnames="settings",
    argvalues=[None, Settings(ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT=False)],
)
async def test_implicit_flow(context_factory, settings):
    username = "username"
    context = context_factory(
        users={username: "password"},
        settings=settings,
    )
    server = context.server
    client = context.clients[0]
    request_url = "https://localhost"
    state = generate_token(10)
    scope = client.scope

    query = Query(
        client_id=client.client_id,
        response_type="token",
        redirect_uri=client.redirect_uris[0],
        scope=scope,
        state=state,
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        settings=context.settings,
    )

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))
    assert fragment["state"] == state
    assert fragment["scope"] == scope


@pytest.mark.asyncio
async def test_password_grant_type_with_client_secret(context_factory):
    username = "username"
    password = "password"
    context = context_factory(users={username: password})
    server = context.server
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret
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
        headers=encode_auth_headers(client_id, client_secret),
    )

    await check_request_validators(request, server.create_token_response)
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_password_grant_type_without_client_secret():
    client = factories.client_factory(client_secret="")
    client_id = client.client_id
    request_url = "https://localhost"
    username = "username"
    password = "password"
    context = factories.context_factory(
        clients=[client],
        users={username: password},
    )
    server = context.server

    post = Post(
        client_id=client_id,
        grant_type="password",
        username=username,
        password=password,
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
async def test_password_grant_type_without_client_secret_using_basic_auth():
    client = factories.client_factory(client_secret="")
    client_id = client.client_id
    request_url = "https://localhost"
    username = "username"
    password = "password"
    context = factories.context_factory(
        clients=[client],
        users={username: password},
    )
    server = context.server

    post = Post(
        grant_type="password",
        password=password,
        username=username,
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
async def test_authorization_code_flow():
    client = factories.client_factory(client_secret="")
    client_id = client.client_id
    redirect_uri = client.redirect_uris[0]

    request_url = "https://localhost"
    username = "username"
    context = factories.context_factory(
        clients=[client],
        users={username: "password"},
    )
    server = context.server

    query = Query(
        client_id=client_id,
        response_type="code",
        redirect_uri=redirect_uri,
        scope=client.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
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
        redirect_uri=redirect_uri,
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
async def test_authorization_code_flow_credentials_in_post():
    client = factories.client_factory(client_secret="")
    client_id = client.client_id
    redirect_uri = client.redirect_uris[0]
    request_url = "https://localhost"
    username = "username"
    context = factories.context_factory(
        clients=[client],
        users={username: "password"},
    )
    server = context.server

    query = Query(
        client_id=client_id,
        response_type="code",
        redirect_uri=redirect_uri,
        scope=client.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
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
        redirect_uri=redirect_uri,
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
async def test_client_credentials_flow_post_data(context: AuthorizationContext):
    server = context.server
    client = context.clients[0]
    request_url = "https://localhost"

    post = Post(
        client_id=client.client_id,
        client_secret=client.client_secret,
        grant_type="client_credentials",
        scope=client.scope,
    )

    request = Request(url=request_url, post=post, method="POST")

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_client_credentials_flow_auth_header(context: AuthorizationContext):
    server = context.server
    client = context.clients[0]
    request_url = "https://localhost"

    post = Post(
        grant_type="client_credentials",
        scope=client.scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
        headers=encode_auth_headers(
            client_id=client.client_id, client_secret=client.client_secret
        ),
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ids=["default_settings", "no_issue_refresh_token_implicit"],
    argnames="settings",
    argvalues=[None, Settings(ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT=False)],
)
async def test_multiple_response_types(context_factory, settings):
    username = "username"
    context = context_factory(
        users={username: "password"},
        settings=Settings(ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT=False),
    )
    server = context.server
    client = context.clients[0]
    request_url = "https://localhost"

    query = Query(
        client_id=client.client_id,
        response_type="code token",
        redirect_uri=client.redirect_uris[0],
        scope=client.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        settings=context.settings,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))

    assert "state" in fragment
    assert "expires_in" in fragment
    assert "access_token" in fragment
    assert "scope" in fragment
    assert "token_type" in fragment
    assert "code" in fragment
    if context.settings.ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT:
        assert "refresh_token_expires_in" in fragment
        assert "refresh_token" in fragment
    else:
        assert "refresh_token_expires_in" not in fragment
        assert "refresh_token" not in fragment


@pytest.mark.asyncio
async def test_response_type_none(context_factory):
    username = "username"
    context = context_factory(users={username: "password"})
    server = context.server
    client = context.clients[0]
    request_url = "https://localhost"

    query = Query(
        client_id=client.client_id,
        response_type="none",
        redirect_uri=client.redirect_uris[0],
        scope=client.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
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
    ids=["default_settings", "no_issue_refresh_token_implicit"],
    argnames="settings",
    argvalues=[None, Settings(ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT=False)],
)
@pytest.mark.parametrize(
    "response_mode,",
    [
        "query",
        "form_post",
        "fragment",
        None,
    ],
)
async def test_response_type_id_token(context_factory, response_mode, settings):
    username = "username"
    context = context_factory(
        users={username: "password"},
        settings=settings,
    )
    server = context.server
    client = context.clients[0]
    request_url = "https://localhost"

    query = Query(
        client_id=client.client_id,
        response_type="code token id_token",
        redirect_uri=client.redirect_uris[0],
        scope=client.scope,
        state=generate_token(10),
        nonce="123",
        response_mode=response_mode,
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        settings=context.settings,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)

    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))
    query = dict(parse_qsl(location.query))

    if response_mode == "fragment" or response_mode is None:
        assert "state" in fragment
        assert "expires_in" in fragment
        assert "access_token" in fragment
        assert "scope" in fragment
        assert "token_type" in fragment
        assert "code" in fragment
        assert "id_token" in fragment
        if context.settings.ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT:
            assert "refresh_token_expires_in" in fragment
            assert "refresh_token" in fragment
        else:
            assert "refresh_token_expires_in" not in fragment
            assert "refresh_token" not in fragment
    elif response_mode == "form_post":
        assert "state" in response.content
        assert "expires_in" in response.content
        assert "access_token" in response.content
        assert "scope" in response.content
        assert "token_type" in response.content
        assert "code" in response.content
        assert "id_token" in response.content
        if context.settings.ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT:
            assert "refresh_token" in response.content
            assert "refresh_token_expires_in" in response.content
        else:
            assert "refresh_token" not in response.content
            assert "refresh_token_expires_in" not in response.content
    elif response_mode == "query":
        assert "state" in query
        assert "expires_in" in query
        assert "access_token" in query
        assert "scope" in query
        assert "token_type" in query
        assert "code" in query
        assert "id_token" in query
        if context.settings.ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT:
            assert "refresh_token" in query
            assert "refresh_token_expires_in" in query
        else:
            assert "refresh_token" not in query
            assert "refresh_token_expires_in" not in query
    else:
        raise AssertionError("Unexpected value of response_mode")
