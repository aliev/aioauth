from http import HTTPStatus
from urllib.parse import parse_qsl, urlparse

import pytest

from aioauth.constances import default_headers
from aioauth.requests import Post, Query, Request
from aioauth.server import AuthorizationServer
from aioauth.storage import BaseStorage
from aioauth.types import (
    CodeChallengeMethod,
    GrantType,
    RequestMethod,
    ResponseMode,
    ResponseType,
)
from aioauth.utils import (
    create_s256_code_challenge,
    encode_auth_headers,
    enforce_list,
    generate_token,
)

from .conftest import Defaults
from .utils import check_request_validators


@pytest.mark.asyncio
async def test_authorization_code_flow_plain_code_challenge(
    server: AuthorizationServer, defaults: Defaults, db: BaseStorage
):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    scope = defaults.scope
    redirect_uri = defaults.redirect_uri
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
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
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        redirect_uri=defaults.redirect_uri,
        code=code,
        code_verifier=code_challenge,
        scope=scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
    assert response.headers == default_headers
    assert response.content["scope"] == scope
    assert response.content["token_type"] == "Bearer"
    # Check that token was created in db
    assert await db.get_token(
        request,
        client_id,
        response.content["access_token"],
        response.content["refresh_token"],
    )

    access_token = response.content["access_token"]
    refresh_token = response.content["refresh_token"]

    post = Post(
        grant_type=GrantType.TYPE_REFRESH_TOKEN,
        refresh_token=refresh_token,
        scope=scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )
    await check_request_validators(request, server.create_token_response)
    response = await server.create_token_response(request)

    assert response.status_code == HTTPStatus.OK
    assert response.content["access_token"] != access_token
    assert response.content["refresh_token"] != refresh_token
    # Check that token was created in db
    assert await db.get_token(
        request,
        client_id,
        response.content["access_token"],
        response.content["refresh_token"],
    )
    # Check that previous token was revoken
    token_in_db = await db.get_token(request, client_id, access_token, refresh_token)
    assert token_in_db.revoked

    # check that scope is previous scope
    new_token = await db.get_token(
        request,
        client_id,
        response.content["access_token"],
        response.content["refresh_token"],
    )
    assert set(enforce_list(new_token.scope)) == set(enforce_list(token_in_db.scope))


@pytest.mark.asyncio
async def test_authorization_code_flow_pkce_code_challenge(
    server: AuthorizationServer, defaults: Defaults, db: BaseStorage
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    code_verifier = generate_token(128)
    scope = defaults.scope
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"
    user = "username"
    state = generate_token(10)

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=scope,
        state=state,
        code_challenge_method=CodeChallengeMethod.S256,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
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
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        redirect_uri=defaults.redirect_uri,
        code=code,
        scope=scope,
        code_verifier=code_verifier,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
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
async def test_implicit_flow(server: AuthorizationServer, defaults: Defaults):
    request_url = "https://localhost"
    state = generate_token(10)
    scope = defaults.scope
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_TOKEN,
        redirect_uri=defaults.redirect_uri,
        scope=scope,
        state=state,
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
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
async def test_password_grant_type(server: AuthorizationServer, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(
        grant_type=GrantType.TYPE_PASSWORD,
        username=defaults.username,
        password=defaults.password,
    )

    request = Request(
        post=post,
        url=request_url,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    await check_request_validators(request, server.create_token_response)
    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_authorization_code_flow(server: AuthorizationServer, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
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
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        redirect_uri=defaults.redirect_uri,
        code=code,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_authorization_code_flow_credentials_in_post(
    server: AuthorizationServer, defaults: Defaults
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
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
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=defaults.redirect_uri,
        code=code,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
    )

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_client_credentials_flow_post_data(
    server: AuthorizationServer, defaults: Defaults
):
    request_url = "https://localhost"

    post = Post(
        grant_type=GrantType.TYPE_CLIENT_CREDENTIALS,
        client_id=defaults.client_id,
        client_secret=defaults.client_secret,
        scope=defaults.scope,
    )

    request = Request(url=request_url, post=post, method=RequestMethod.POST)

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_client_credentials_flow_auth_header(
    server: AuthorizationServer, defaults: Defaults
):
    request_url = "https://localhost"

    post = Post(
        grant_type=GrantType.TYPE_CLIENT_CREDENTIALS,
        scope=defaults.scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(
            client_id=defaults.client_id, client_secret=defaults.client_secret
        ),
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_multiple_response_types(server: AuthorizationServer, defaults: Defaults):
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=f"{ResponseType.TYPE_CODE} {ResponseType.TYPE_TOKEN}",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
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
async def test_response_type_none(server: AuthorizationServer, defaults: Defaults):
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_NONE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
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
        ResponseMode.MODE_FORM_POST,
        ResponseMode.MODE_FRAGMENT,
        ResponseMode.MODE_QUERY,
        None,
    ],
)
async def test_response_type_id_token(
    server: AuthorizationServer, defaults: Defaults, response_mode
):
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=f"{ResponseType.TYPE_CODE} {ResponseType.TYPE_TOKEN} {ResponseType.TYPE_ID_TOKEN}",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        nonce="123",
        response_mode=response_mode,
    )

    request = Request(
        url=request_url,
        query=query,
        method=RequestMethod.GET,
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)

    location = response.headers["location"]
    location = urlparse(location)
    fragment = dict(parse_qsl(location.fragment))
    query = dict(parse_qsl(location.query))

    if response_mode == ResponseMode.MODE_FRAGMENT:
        assert "state" in fragment
        assert "expires_in" in fragment
        assert "refresh_token_expires_in" in fragment
        assert "access_token" in fragment
        assert "refresh_token" in fragment
        assert "scope" in fragment
        assert "token_type" in fragment
        assert "code" in fragment
        assert "id_token" in fragment
    elif response_mode == ResponseMode.MODE_FORM_POST:
        assert "state" in response.content
        assert "expires_in" in response.content
        assert "refresh_token_expires_in" in response.content
        assert "access_token" in response.content
        assert "refresh_token" in response.content
        assert "scope" in response.content
        assert "token_type" in response.content
        assert "code" in response.content
        assert "id_token" in response.content
    elif response_mode == ResponseMode.MODE_QUERY:
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
