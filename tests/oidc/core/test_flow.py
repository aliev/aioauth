from http import HTTPStatus
from typing import Optional

import pytest

from aioauth.oidc.core.requests import Query, Request
from aioauth.server import AuthorizationServer
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
