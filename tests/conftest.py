import time
from typing import Dict, Type

import pytest

from aioauth.config import Settings
from aioauth.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import Request
from aioauth.response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeIdToken,
    ResponseTypeNone,
    ResponseTypeToken,
)
from aioauth.server import AuthorizationServer
from aioauth.utils import generate_token

from .classes import Storage, get_db_class
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


@pytest.fixture
def settings() -> Settings:
    return Settings(INSECURE_TRANSPORT=True)


@pytest.fixture
def storage(defaults: Defaults, settings: Settings) -> Dict:
    client = Client(
        client_id=defaults.client_id,
        client_secret=defaults.client_secret,
        grant_types=[
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "password",
        ],
        redirect_uris=[defaults.redirect_uri],
        response_types=[
            "code",
            "token",
            "none",
            "id_token",
        ],
        scope=defaults.scope,
    )

    authorization_code = AuthorizationCode(
        code=defaults.code,
        client_id=defaults.client_id,
        response_type="code",
        auth_time=int(time.time()),
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        code_challenge_method="plain",
        expires_in=settings.AUTHORIZATION_CODE_EXPIRES_IN,
    )

    token = Token(
        client_id=defaults.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
        refresh_token_expires_in=settings.REFRESH_TOKEN_EXPIRES_IN,
        access_token=defaults.access_token,
        refresh_token=defaults.refresh_token,
        issued_at=int(time.time()),
        scope=defaults.scope,
    )

    return {
        "tokens": [token],
        "authorization_codes": [authorization_code],
        "clients": [client],
    }


@pytest.fixture
def db_class(defaults: Defaults, storage) -> Type[Storage]:
    return get_db_class(defaults, storage)


@pytest.fixture
def db(db_class: Type[Storage]):
    return db_class()


@pytest.fixture
def server(db: Storage) -> AuthorizationServer[Request, Storage]:
    server = AuthorizationServer[Request, Storage](
        storage=db,
        response_types={
            "token": ResponseTypeToken[Request, Storage],
            "code": ResponseTypeAuthorizationCode[Request, Storage],
            "none": ResponseTypeNone[Request, Storage],
            "id_token": ResponseTypeIdToken[Request, Storage],
        },
        grant_types={
            "authorization_code": AuthorizationCodeGrantType[Request, Storage],
            "client_credentials": ClientCredentialsGrantType[Request, Storage],
            "password": PasswordGrantType[Request, Storage],
            "refresh_token": RefreshTokenGrantType[Request, Storage],
        },
    )
    return server
