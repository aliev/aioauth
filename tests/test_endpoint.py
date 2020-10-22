from http import HTTPStatus
from typing import Dict, Type

import pytest
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Request
from async_oauth2_provider.types import (
    EndpointType,
    ErrorType,
    GrantType,
    RequestMethod,
)
from tests.models import Defaults
from tests.utils import set_authorization_headers


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
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_introspection_response(request)
    assert not response.content.active
    assert response.status_code == HTTPStatus.OK


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
