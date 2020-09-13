import pytest
from async_asgi_testclient.testing import TestClient
from starlette import status


@pytest.mark.asyncio
async def test_auth(client: TestClient):
    response = await client.post("/oauth/v2/token")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
