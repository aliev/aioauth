from http import HTTPStatus
from typing import Dict

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Request
from async_oauth2_provider.types import GrantType, RequestMethod
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
