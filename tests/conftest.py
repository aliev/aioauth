import pytest

from aioauth.requests import Request
from aioauth.server import AuthorizationServer

from tests import factories
from tests.classes import AuthorizationContext, Storage


@pytest.fixture
def context_factory():
    return factories.context_factory


@pytest.fixture
def context() -> AuthorizationContext:
    yield factories.context_factory()


@pytest.fixture
def server(context) -> AuthorizationServer[Request, Storage]:
    yield context.server
