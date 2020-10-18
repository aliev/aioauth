from http import HTTPStatus
from typing import Dict

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Request
from async_oauth2_provider.types import ErrorType, GrantType, RequestMethod
from tests.models import Defaults
from tests.utils import set_authorization_headers


@pytest.mark.asyncio
async def test_missing_grant_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post()

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_REQUEST
    assert response.content.description == "Request is missing grant type."


@pytest.mark.asyncio
async def test_invalid_grant_type(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post(grant_type="invalid")

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.UNSUPPORTED_GRANT_TYPE

    storage["clients"][0].client_metadata.grant_types = [
        GrantType.TYPE_AUTHORIZATION_CODE
    ]

    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post(grant_type=GrantType.TYPE_PASSWORD)

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.UNSUPPORTED_GRANT_TYPE


@pytest.mark.asyncio
async def test_invalid_client(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = "invalid"
    client_secret = "invalid"

    post = Post(grant_type=GrantType.TYPE_PASSWORD)

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_REQUEST


@pytest.mark.asyncio
async def test_password_grant_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post(
        grant_type=GrantType.TYPE_PASSWORD,
        password=defaults.password,
        username=defaults.username,
    )

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK

    # Empty password
    post = Post(grant_type=GrantType.TYPE_PASSWORD, username=defaults.username,)

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert response.content.description == "Invalid credentials given."

    # Empty username

    post = Post(grant_type=GrantType.TYPE_PASSWORD, password=defaults.password,)

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert response.content.description == "Invalid credentials given."

    # Invalid username or password

    post = Post(
        grant_type=GrantType.TYPE_PASSWORD,
        password="some pass",
        username="some username",
    )

    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert response.content.description == "Invalid credentials given."


@pytest.mark.asyncio
async def test_empty_refresh_token(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post(grant_type=GrantType.TYPE_REFRESH_TOKEN,)
    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_REQUEST
    assert response.content.description == "Missing refresh token parameter."


@pytest.mark.asyncio
async def test_invalid_refresh_token(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post(grant_type=GrantType.TYPE_REFRESH_TOKEN, refresh_token="invalid")
    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT


@pytest.mark.asyncio
async def test_refresh_token_expired(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post(grant_type=GrantType.TYPE_REFRESH_TOKEN, refresh_token="invalid")
    request = Request(
        url="https://localhost",
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
