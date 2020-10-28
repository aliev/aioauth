import time
from http import HTTPStatus
from typing import Dict, List, Type

import pytest
from async_oauth2_provider.config import settings
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.models import Token
from async_oauth2_provider.requests import Post, Request
from async_oauth2_provider.types import (
    EndpointType,
    ErrorType,
    GrantType,
    RequestMethod,
)
from async_oauth2_provider.utils import encode_auth_headers, generate_token
from tests.models import Defaults


@pytest.mark.asyncio
async def test_invalid_token(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"
    token = "invalid token"

    post = Post(token=token)
    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_introspection_response(request)
    assert not response.content.active
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_expired_token(
    endpoint: OAuth2Endpoint, storage: Dict[str, List], defaults: Defaults
):
    token = Token(
        client_id=defaults.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
        access_token=generate_token(42),
        refresh_token=generate_token(48),
        issued_at=int(time.time() - settings.TOKEN_EXPIRES_IN),
        scope=defaults.scope,
    )

    client_id = defaults.client_id
    client_secret = defaults.client_secret

    storage["tokens"].append(token)

    post = Post(token=token.access_token)
    request = Request(
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.OK
    assert not response.content.active


@pytest.mark.asyncio
async def test_valid_token(
    endpoint: OAuth2Endpoint, storage: Dict[str, List], defaults: Defaults
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret

    token = storage["tokens"][0]

    post = Post(token=token.access_token)
    request = Request(
        post=post,
        method=RequestMethod.POST,
        headers=encode_auth_headers(client_id, client_secret),
    )

    response = await endpoint.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.OK
    assert response.content.active


@pytest.mark.asyncio
async def test_unregister_endpoint(endpoint: OAuth2Endpoint):
    assert endpoint.grant_type.get(GrantType.TYPE_AUTHORIZATION_CODE) is not None
    endpoint.unregister(EndpointType.GRANT_TYPE, GrantType.TYPE_AUTHORIZATION_CODE)
    assert endpoint.grant_type.get(GrantType.TYPE_AUTHORIZATION_CODE) is None


@pytest.mark.asyncio
async def test_endpoint_availability(db_class: Type[DBBase]):
    endpoint = OAuth2Endpoint(db=db_class(), available=False)
    request = Request(method=RequestMethod.POST)
    response = await endpoint.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.content.error == ErrorType.TEMPORARILY_UNAVAILABLE
