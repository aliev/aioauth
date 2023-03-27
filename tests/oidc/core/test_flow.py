from http import HTTPStatus
from typing import Optional
from urllib.parse import parse_qsl, urlparse

import pytest

from aioauth.oidc.core.requests import Query, Request
from aioauth.oidc.core.grant_type import AuthorizationCodeGrantType
from aioauth.requests import Post
from aioauth.server import AuthorizationServer
from aioauth.storage import TStorage
from aioauth.utils import (
    generate_token,
)

from tests.conftest import Defaults
from tests.utils import check_request_validators


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user, expected_status_code",
    [
        ("username", HTTPStatus.FOUND),
        (None, HTTPStatus.UNAUTHORIZED),
    ],
)
async def test_authorization_endpoint_allows_prompt_query_param(
    defaults: Defaults,
    expected_status_code: HTTPStatus,
    server: AuthorizationServer,
    user: Optional[str],
):
    client_id = defaults.client_id
    request_url = "https://localhost"

    query = Query(
        client_id=client_id,
        prompt="none",
        response_type="code",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
        user=user,
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)
    assert response.status_code == expected_status_code


@pytest.mark.asyncio
@pytest.mark.override_defaults(client_secret="")
@pytest.mark.override_server(
    grant_types={
        "authorization_code": AuthorizationCodeGrantType[Request, TStorage],
    },
)
async def test_authorization_code_flow_token_response_includes_id_token(
    server: AuthorizationServer,
    defaults: Defaults,
):
    client_id = defaults.client_id
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=defaults.client_id,
        response_type="code",
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
    )

    request = Request(
        url=request_url,
        query=query,
        method="GET",
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
        client_id=client_id,
        code=code,
        grant_type="authorization_code",
        redirect_uri=defaults.redirect_uri,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
    )

    await check_request_validators(request, server.create_token_response)

    response = await server.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
    assert "id_token" in response.content
