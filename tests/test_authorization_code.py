from base64 import b64encode
from http import HTTPStatus

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Query, Request
from async_oauth2_provider.types import GrantType, RequestMethod, ResponseType
from tests.conftest import Defaults

# from urllib.parse import urlparse


@pytest.mark.asyncio
async def test_response_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_TOKEN,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state="test",
    )
    request = Request(
        url="https://google.com/",
        query=query,
        method=RequestMethod.GET,
        user="some user",
    )

    response = await endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND


@pytest.mark.asyncio
async def test_grant_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    """ Simple smoke test """
    post = Post(
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        redirect_uri=defaults.redirect_uri,
        code=defaults.code,
    )
    authorization = b64encode(
        f"{defaults.client_id}:{defaults.client_secret}".encode("ascii")
    )
    headers = {"Authorization": f"basic {authorization.decode()}"}
    request = Request(
        url="https://google.com", post=post, method=RequestMethod.POST, headers=headers
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
