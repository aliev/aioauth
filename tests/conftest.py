from typing import Any, Generator
import pytest

from aioauth.server import AuthorizationServer

from tests import factories
from tests.classes import AuthorizationContext


@pytest.fixture
def context_factory():
    return factories.context_factory


@pytest.fixture
def context() -> Generator[AuthorizationContext, Any, Any]:
    yield factories.context_factory()


@pytest.fixture
def server(
    context: AuthorizationContext,
) -> Generator[AuthorizationServer, Any, Any]:
    yield context.server
