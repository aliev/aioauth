from typing import Any, Callable, Dict, Type

import pytest

from aioauth.config import Settings
from aioauth.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    PasswordGrantType,
    RefreshTokenGrantType,
)
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
from tests.classes import (
    BasicServerConfig,
    Storage,
    StorageConfig,
    QueryableAuthorizationServer,
)


@pytest.fixture
def defaults_factory() -> BasicServerConfig:
    return factories.defaults_factory


@pytest.fixture
def defaults(request, defaults_factory) -> BasicServerConfig:
    marker = request.node.get_closest_marker("override_defaults")
    kwargs = marker.kwargs if marker else {}

    yield defaults_factory(**kwargs)


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
    default_grant_types = {
        "authorization_code": AuthorizationCodeGrantType[Request, Storage],
        "client_credentials": ClientCredentialsGrantType[Request, Storage],
        "password": PasswordGrantType[Request, Storage],
        "refresh_token": RefreshTokenGrantType[Request, Storage],
    }
    default_response_types = {
        "code": ResponseTypeAuthorizationCode[Request, Storage],
        "id_token": ResponseTypeIdToken[Request, Storage],
        "none": ResponseTypeNone[Request, Storage],
        "token": ResponseTypeToken[Request, Storage],
    }

    def _default_server_factory(
        grant_types: Dict[GrantType, Any] = default_grant_types,
        response_types: Dict[ResponseType, Any] = default_response_types,
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
