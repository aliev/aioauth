import pytest
from async_asgi_testclient.testing import TestClient
from fastapi_oauth2.tables import ClientTable
from starlette import status


@pytest.mark.asyncio
async def test_auth(client: TestClient, client_record: ClientTable):
    response = await client.post("/oauth/v2/token")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
