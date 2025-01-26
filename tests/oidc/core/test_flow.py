from http import HTTPStatus

import pytest

from aioauth.oidc.core.requests import Query, Request
from aioauth.utils import (
    generate_token,
)

from tests.utils import check_request_validators


@pytest.mark.asyncio
async def test_authorization_endpoint_allows_prompt_query_param(context_factory):
    context = context_factory()
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
    )

    await check_request_validators(request, server.create_authorization_response)

    response = await server.create_authorization_response(request)
    assert response.status_code == HTTPStatus.FOUND
