from urllib.parse import parse_qsl, urlparse

import pytest
from async_asgi_testclient.testing import TestClient
from async_oauth2_provider.types import GrantType, ResponseType
from fastapi_oauth2.tables import ClientTable
from sqlalchemy.util.compat import b64encode
from starlette import status
from starlette.status import HTTP_200_OK


@pytest.mark.asyncio
async def test_auth(client: TestClient, client_record: ClientTable):
    response = await client.post("/oauth/v2/token")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_authorization_code_flow(client: TestClient, client_record: ClientTable):
    # Check get method
    query = {
        "client_id": client_record.client_id,
        "redirect_uri": client_record.client_metadata["redirect_uris"][0],
        "response_type": ResponseType.TYPE_CODE.value,
        "state": "some random state",
        "scope": client_record.client_metadata["scope"],
    }
    response = await client.get("/oauth/v2/authorize", query_string=query)
    assert response.status_code == status.HTTP_200_OK

    # Get authorization code
    response = await client.post("/oauth/v2/authorize", query_string=query)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    # Authorize to get the authorization code
    data = {
        "username": "admin",
        "password": "admin",
    }

    response = await client.post(
        "/oauth/v2/authorize", query_string=query, form=data, allow_redirects=False
    )
    assert response.status_code == status.HTTP_302_FOUND
    redirect_uri = urlparse(response.headers["location"])

    query = dict(parse_qsl(redirect_uri.query))

    # Check authorization code and get the token

    data = {
        "code": query["code"],
        "grant_type": GrantType.TYPE_AUTHORIZATION_CODE.value,
        "redirect_uri": client_record.client_metadata["redirect_uris"][0],
        "scope": client_record.client_metadata["scope"],
    }
    authorization = b64encode(
        f"{client_record.client_id}:{client_record.client_secret}".encode("ascii")
    )
    headers = {"Authorization": f"basic {authorization}"}

    response = await client.post("/oauth/v2/token", form=data, headers=headers)
    assert response.status_code == HTTP_200_OK
    assert "access_token" in response.json()
