import pytest

from aioauth.config import Settings
from aioauth.requests import Request
from aioauth.server import AuthorizationServer

from tests import factories
from tests.authorization_context import AuthorizationContext
from tests.classes import (
    Defaults,
    Storage,
)


@pytest.fixture
def context_factory():
    return factories.context_factory


@pytest.fixture
def context() -> AuthorizationContext:
    return factories.context_factory()


@pytest.fixture
def defaults(context) -> Defaults:
    client = context.clients[0]
    token = context.initial_tokens[0]
    code = context.initial_authorization_codes[0]
    usernames = list(context.users.keys())
    username = usernames[0] if usernames else ""
    password = context.users.get(username, "")
    redirect_uri = client.redirect_uris[0]

    yield Defaults(
        client_id=client.client_id,
        client_secret=client.client_secret,
        code=code,
        refresh_token=token.refresh_token,
        access_token=token.access_token,
        username=username,
        password=password,
        redirect_uri=redirect_uri,
        scope=client.scope,
    )


@pytest.fixture
def settings(context) -> Settings:
    return context.settings


@pytest.fixture
def db(context):
    return context.storage


@pytest.fixture
def server(context) -> AuthorizationServer[Request, Storage]:
    return context.server
