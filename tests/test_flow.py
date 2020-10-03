from http import HTTPStatus
from urllib.parse import parse_qsl, urlparse

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Query, Request
from async_oauth2_provider.types import (
    CodeChallengeMethod,
    GrantType,
    RequestMethod,
    ResponseType,
)
from async_oauth2_provider.utils import create_s256_code_challenge, generate_token
from tests.conftest import Defaults
from tests.utils import set_authorization_headers


@pytest.mark.asyncio
async def test_plain_code_challenge(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )
    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
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
        code_verifier=code_challenge,
    )

    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_pkce(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)

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
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
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

    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_implicit_flow(endpoint: OAuth2Endpoint, defaults: Defaults):
    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_TOKEN,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )
    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
    )

    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.FOUND


@pytest.mark.asyncio
async def test_authorization_code_flow(endpoint: OAuth2Endpoint, defaults: Defaults):
    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )
    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
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

    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
