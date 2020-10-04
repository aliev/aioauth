import time
from typing import Type

import pytest
from async_oauth2_provider.config import settings
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from async_oauth2_provider.models import (
    AuthorizationCode,
    Client,
    ClientMetadata,
    Token,
)
from async_oauth2_provider.response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeToken,
)
from async_oauth2_provider.types import (
    CodeChallengeMethod,
    EndpointType,
    GrantType,
    ResponseType,
)
from async_oauth2_provider.utils import generate_token

from .classes import get_db_class
from .models import Defaults


@pytest.fixture
def defaults() -> Defaults:
    return Defaults(
        client_id=generate_token(48),
        client_secret=generate_token(48),
        code=generate_token(5),
        refresh_token=generate_token(48),
        access_token=generate_token(42),
        username="root",
        password="toor",
        redirect_uri="https://ownauth.com/callback",
        scope="read write",
    )


@pytest.fixture()
def storage(defaults: Defaults) -> dict:
    client_metadata = ClientMetadata(
        grant_types=[
            GrantType.TYPE_AUTHORIZATION_CODE,
            GrantType.TYPE_CLIENT_CREDENTIALS,
            GrantType.TYPE_REFRESH_TOKEN,
            GrantType.TYPE_PASSWORD,
        ],
        redirect_uris=[defaults.redirect_uri],
        response_types=[ResponseType.TYPE_CODE, ResponseType.TYPE_TOKEN],
        scope=defaults.scope,
    )

    client = Client(
        client_id=defaults.client_id,
        client_secret=defaults.client_secret,
        client_metadata=client_metadata,
    )

    authorization_code = AuthorizationCode(
        code=defaults.code,
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        auth_time=time.time(),
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        code_challenge_method=CodeChallengeMethod.PLAIN,
    )

    token = Token(
        client_id=defaults.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
        access_token=defaults.access_token,
        refresh_token=defaults.refresh_token,
        issued_at=time.time(),
        scope=defaults.scope,
    )

    return {
        "tokens": [token],
        "authorization_codes": [authorization_code],
        "clients": [client],
    }


@pytest.fixture
def db_class(defaults: Defaults, storage) -> Type[DBBase]:
    return get_db_class(defaults, storage)


@pytest.fixture
def endpoint(db_class: Type[DBBase]) -> OAuth2Endpoint:
    endpoint = OAuth2Endpoint(db=db_class())
    # Register response type endpoints
    endpoint.register(
        EndpointType.RESPONSE_TYPE, ResponseType.TYPE_TOKEN, ResponseTypeToken,
    )
    endpoint.register(
        EndpointType.RESPONSE_TYPE,
        ResponseType.TYPE_CODE,
        ResponseTypeAuthorizationCode,
    )

    # Register grant type endpoints
    endpoint.register(
        EndpointType.GRANT_TYPE,
        GrantType.TYPE_AUTHORIZATION_CODE,
        AuthorizationCodeGrantType,
    )
    endpoint.register(
        EndpointType.GRANT_TYPE,
        GrantType.TYPE_CLIENT_CREDENTIALS,
        ClientCredentialsGrantType,
    )
    endpoint.register(
        EndpointType.GRANT_TYPE, GrantType.TYPE_PASSWORD, PasswordGrantType,
    )
    endpoint.register(
        EndpointType.GRANT_TYPE, GrantType.TYPE_REFRESH_TOKEN, RefreshTokenGrantType,
    )
    return endpoint
