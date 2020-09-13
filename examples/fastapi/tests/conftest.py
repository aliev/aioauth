import logging
import time
from typing import Iterator

import pytest
from alembic.config import main
from async_asgi_testclient import TestClient
from async_oauth2_provider.types import GrantType, ResponseType
from async_oauth2_provider.utils import generate_token
from fastapi_oauth2.main import app as app_
from fastapi_oauth2.tables import ClientTable


@pytest.fixture(autouse=True)
def migrations():
    # Disable alembic logger
    logger = logging.getLogger("alembic.runtime.migration")
    logger.disabled = True

    # Run migrations
    main(["--raiseerr", "upgrade", "head"])
    yield
    # Downgrade
    main(["--raiseerr", "downgrade", "base"])


@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def app():
    return app_


@pytest.fixture(autouse=True)
@pytest.mark.asyncio
async def client(app) -> Iterator[TestClient]:
    async with TestClient(app) as client:
        yield client


@pytest.fixture
@pytest.mark.asyncio
async def client_record():
    client_table = ClientTable(
        client_id=generate_token(24),
        client_secret=generate_token(),
        client_id_issued_at=int(time.time()),
        client_secret_expires_at=int(time.time()),
    )

    client_metadata = {
        "grant_types": [
            GrantType.TYPE_AUTHORIZATION_CODE.value,
            GrantType.TYPE_PASSWORD.value,
            GrantType.TYPE_CLIENT_CREDENTIALS.value,
            GrantType.TYPE_REFRESH_TOKEN.value,
        ],
        "response_types": [ResponseType.TYPE_TOKEN.value, ResponseType.TYPE_CODE.value],
        "redirect_uris": ["https://ownauth.com/callback"],
        "scope": "read write",
    }

    client_table.set_client_metadata(client_metadata)

    return await client_table.create()
