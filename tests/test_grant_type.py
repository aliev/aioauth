import logging
from http import HTTPStatus
from typing import Dict

import pytest
from _pytest.logging import LogCaptureFixture
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Request
from async_oauth2_provider.types import ErrorType, GrantType, RequestMethod
from tests.models import Defaults
from tests.utils import set_authorization_headers


@pytest.mark.asyncio
async def test_missing_grant_type(
    endpoint: OAuth2Endpoint, defaults: Defaults, caplog: LogCaptureFixture
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post()

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_REQUEST
    assert response.content.description == "Request is missing grant type."
    assert ErrorType.INVALID_REQUEST in caplog.text


@pytest.mark.asyncio
async def test_invalid_grant_type(
    endpoint: OAuth2Endpoint,
    defaults: Defaults,
    storage: Dict,
    caplog: LogCaptureFixture,
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"
    grant_type = "invalid"

    post = Post(
        grant_type=grant_type  # type: ignore
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.UNSUPPORTED_GRANT_TYPE
    assert ErrorType.UNSUPPORTED_GRANT_TYPE in caplog.text

    storage["clients"][0].client_metadata.grant_types = [
        GrantType.TYPE_AUTHORIZATION_CODE
    ]

    client_id = defaults.client_id
    client_secret = defaults.client_secret

    post = Post(grant_type=GrantType.TYPE_PASSWORD)

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.UNAUTHORIZED_CLIENT


@pytest.mark.asyncio
async def test_invalid_client(
    endpoint: OAuth2Endpoint, defaults: Defaults, caplog: LogCaptureFixture
):
    client_id = "invalid"
    client_secret = "invalid"
    request_url = "https://localhost"

    post = Post(grant_type=GrantType.TYPE_PASSWORD)

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_REQUEST
    assert ErrorType.INVALID_REQUEST in caplog.text


@pytest.mark.asyncio
async def test_password_grant_type(
    endpoint: OAuth2Endpoint, defaults: Defaults, caplog: LogCaptureFixture
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(
        grant_type=GrantType.TYPE_PASSWORD,
        password=defaults.password,
        username=defaults.username,
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK

    # Empty password
    post = Post(grant_type=GrantType.TYPE_PASSWORD, username=defaults.username,)

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )

    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert response.content.description == "Invalid credentials given."
    assert ErrorType.INVALID_GRANT in caplog.text

    # Empty username

    post = Post(grant_type=GrantType.TYPE_PASSWORD, password=defaults.password,)

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert response.content.description == "Invalid credentials given."
    assert ErrorType.INVALID_GRANT in caplog.text

    # Invalid username or password

    post = Post(
        grant_type=GrantType.TYPE_PASSWORD,
        password="some pass",
        username="some username",
    )

    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert response.content.description == "Invalid credentials given."
    assert ErrorType.INVALID_GRANT in caplog.text


@pytest.mark.asyncio
async def test_empty_refresh_token(
    endpoint: OAuth2Endpoint, defaults: Defaults, caplog: LogCaptureFixture
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(grant_type=GrantType.TYPE_REFRESH_TOKEN,)
    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_REQUEST
    assert response.content.description == "Missing refresh token parameter."
    assert ErrorType.INVALID_REQUEST in caplog.text


@pytest.mark.asyncio
async def test_invalid_refresh_token(
    endpoint: OAuth2Endpoint, defaults: Defaults, caplog: LogCaptureFixture
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(grant_type=GrantType.TYPE_REFRESH_TOKEN, refresh_token="invalid")
    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert ErrorType.INVALID_GRANT in caplog.text


@pytest.mark.asyncio
async def test_refresh_token_expired(
    endpoint: OAuth2Endpoint, defaults: Defaults, caplog: LogCaptureFixture
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(grant_type=GrantType.TYPE_REFRESH_TOKEN, refresh_token="invalid")
    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    with caplog.at_level(logging.DEBUG):
        response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.INVALID_GRANT
    assert ErrorType.INVALID_GRANT in caplog.text
