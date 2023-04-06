from http import HTTPStatus
from typing import Optional

import pytest

from aioauth.oidc.core.requests import Query, Request
from aioauth.utils import (
    generate_token,
)

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
    expected_status_code: HTTPStatus,
    user: Optional[str],
    context_factory,
):
    context = context_factory(users={user, "password"})
    server = context.server
    client = context.clients[0]
    client_id = client.client_id
    request_url = "https://localhost"

    query = Query(
        client_id=client_id,
        prompt="none",
        response_type="code",
        redirect_uri=client.redirect_uris[0],
        scope=client.scope,
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
