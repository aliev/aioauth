from urllib.parse import parse_qs, urlparse

import pytest
from async_asgi_testclient.testing import TestClient
from async_oauth2_provider.types import ResponseType
from fastapi_oauth2.tables import ClientTable
from starlette import status


@pytest.mark.asyncio
async def test_auth(client: TestClient, client_record: ClientTable):
    response = await client.post("/oauth/v2/token")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_authorization_code_flow(client: TestClient, client_record: ClientTable):
    query = {
        "client_id": client_record.client_id,
        "redirect_uri": client_record.client_metadata["redirect_uris"][0],
        "response_type": ResponseType.TYPE_CODE.value,
        "state": "some random state",
        "scope": client_record.client_metadata["scope"],
    }
    response = await client.get("/oauth/v2/authorize", query_string=query)
    assert response.status_code == status.HTTP_200_OK

    response = await client.post("/oauth/v2/authorize", query_string=query)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    data = {
        "username": "admin",
        "password": "admin",
    }

    response = await client.post(
        "/oauth/v2/authorize", query_string=query, form=data, allow_redirects=False
    )
    assert response.status_code == status.HTTP_302_FOUND
    redirect_uri = urlparse(response.headers["location"])
    query = parse_qs(redirect_uri.query)
