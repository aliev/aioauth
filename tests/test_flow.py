from http import HTTPStatus
from urllib.parse import parse_qsl, urlparse

import pytest
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Query, Request
from async_oauth2_provider.types import (
    CodeChallengeMethod,
    GrantType,
    RequestMethod,
    ResponseType,
)
from async_oauth2_provider.utils import (
    create_s256_code_challenge,
    encode_auth_headers,
    generate_token,
)
from tests.conftest import Defaults

from .utils import check_request_validators


@pytest.mark.asyncio
async def test_authorization_code_flow_plan_code_challenge(
    endpoint: OAuth2Endpoint, defaults: Defaults, db: DBBase
):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    scope = defaults.scope
    state = generate_token(10)
    redirect_uri = defaults.redirect_uri
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )

    await check_request_validators(request, endpoint.create_authorization_code_response)
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.FOUND
    assert "code" in response.headers["location"]
    assert "scope" in response.headers["location"]
    assert "state" in response.headers["location"]

    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]

    post = Post(
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        redirect_uri=defaults.redirect_uri,
        code=code,
        code_verifier=code_challenge,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK

    access_token = response.content.access_token
    refresh_token = response.content.refresh_token

    post = Post(grant_type=GrantType.TYPE_REFRESH_TOKEN, refresh_token=refresh_token,)

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )
    await check_request_validators(request, endpoint.create_token_response)
    response = await endpoint.create_token_response(request)

    assert response.status_code == HTTPStatus.OK
    assert response.content.access_token != access_token
    assert response.content.refresh_token != refresh_token
    token_in_db = await db.get_token(request, client_id, access_token, refresh_token)
    assert token_in_db.revoked


@pytest.mark.asyncio
async def test_authorization_code_flow_pkce_code_challenge(
    endpoint: OAuth2Endpoint, defaults: Defaults, db: DBBase
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.S256,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.FOUND

    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]

    post = Post(
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        redirect_uri=defaults.redirect_uri,
        code=code,
        code_verifier=code_verifier,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    await check_request_validators(request, endpoint.create_token_response)

    code_record = await db.get_authorization_code(request, client_id, code)
    assert code_record

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK

    code_record = await db.get_authorization_code(request, client_id, code)
    assert not code_record


@pytest.mark.asyncio
async def test_implicit_flow(endpoint: OAuth2Endpoint, defaults: Defaults):
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_TOKEN,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )

    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.FOUND


@pytest.mark.asyncio
async def test_password_grant_type(endpoint: OAuth2Endpoint, defaults: Defaults):
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

    await check_request_validators(request, endpoint.create_token_response)
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_authorization_code_flow(endpoint: OAuth2Endpoint, defaults: Defaults):
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
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )

    response = await endpoint.create_authorization_code_response(request)
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

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
