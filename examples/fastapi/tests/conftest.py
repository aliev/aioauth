import logging
from typing import Iterator

import pytest
from alembic.config import main
from async_asgi_testclient import TestClient
from fastapi_oauth2.main import app as app_


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
