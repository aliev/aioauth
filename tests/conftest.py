from typing import Any, Callable, Dict, Type

import pytest

from aioauth.config import Settings
from aioauth.requests import Request
from aioauth.response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeIdToken,
    ResponseTypeNone,
    ResponseTypeToken,
)
from aioauth.server import AuthorizationServer
from aioauth.types import GrantType, ResponseType

from tests import factories
from tests.authorization_context import AuthorizationContext
from tests.classes import (
    BasicServerConfig,
    Storage,
    StorageConfig,
    QueryableAuthorizationServer,
)


DEFAULT_RESPONSE_TYPES = {
    "code": ResponseTypeAuthorizationCode[Request, Storage],
    "id_token": ResponseTypeIdToken[Request, Storage],
    "none": ResponseTypeNone[Request, Storage],
    "token": ResponseTypeToken[Request, Storage],
}


@pytest.fixture
def defaults(request, context) -> BasicServerConfig:
    marker = request.node.get_closest_marker("override_defaults")
    kwargs = marker.kwargs if marker else {}
    print(context)

    default_client = context.clients[0]
    default_token = context.initial_tokens[0]
    default_access_token = default_token.access_token
    default_refresh_token = default_token.refresh_token
    default_code = context.initial_authorization_codes[0]
    usernames = list(context.users.keys())
    default_user = usernames[0] if usernames else ""
    default_password = context.users.get(default_user, "")
    default_redirect_uri = default_client.redirect_uris[0]

    access_token: str = kwargs.get("access_token", default_access_token)
    client_id: str = kwargs.get("client_id", default_client.client_id)
    client_secret: str = kwargs.get("client_secret", default_client.client_secret)
    code: str = kwargs.get("code", default_code)
    password: str = kwargs.get("password", default_password)
    redirect_uri: str = kwargs.get("redirect_uri", default_redirect_uri)
    refresh_token: str = kwargs.get("refresh_token", default_refresh_token)
    scope: str = kwargs.get("scope", default_client.scope)
    username: str = kwargs.get("username", default_user)

    yield BasicServerConfig(
        client_id=client_id,
        client_secret=client_secret,
        code=code,
        refresh_token=refresh_token,
        access_token=access_token,
        username=username,
        password=password,
        redirect_uri=redirect_uri,
        scope=scope,
    )


@pytest.fixture
def settings() -> Settings:
    return Settings(INSECURE_TRANSPORT=True)


@pytest.fixture
def storage_config_factory() -> Callable[[...], StorageConfig]:
    return factories.storage_config_factory


@pytest.fixture
def storage_config(
    defaults: BasicServerConfig,
    settings: Settings,
    storage_config_factory: Callable[[...], StorageConfig],
) -> StorageConfig:
    return storage_config_factory(defaults=defaults, settings=settings)


@pytest.fixture
def storage_factory() -> Callable[[StorageConfig], Storage]:
    return factories.storage_factory


@pytest.fixture
def db(storage_factory: Type[Storage], storage_config: StorageConfig):
    return storage_factory(storage_config=storage_config)


@pytest.fixture
def default_server_factory(db: Storage):
    def _default_server_factory(
        grant_types: Dict[GrantType, Any] = factories.grant_types_factory(),
        response_types: Dict[ResponseType, Any] = DEFAULT_RESPONSE_TYPES,
        storage: Storage = db,
    ) -> AuthorizationServer:
        return QueryableAuthorizationServer[Request, Storage](
            grant_types=grant_types,
            response_types=response_types,
            storage=db,
        )

    return _default_server_factory


@pytest.fixture
def server(default_server_factory) -> AuthorizationServer[Request, Storage]:
    return default_server_factory()


@pytest.fixture
def context() -> AuthorizationContext:
    return factories.context_factory()
