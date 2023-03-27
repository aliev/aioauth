import time
from typing import Dict

from aioauth.config import Settings
from aioauth.models import AuthorizationCode, Client, Token
from aioauth.utils import generate_token

from tests.classes import BasicServerConfig, Storage, StorageConfig


def defaults_factory(
    access_token: str = generate_token(42),
    client_id: str = generate_token(48),
    client_secret: str = generate_token(48),
    code: str = generate_token(5),
    password: str = "toor",
    redirect_uri: str = "https://ownauth.com/callback",
    refresh_token: str = generate_token(48),
    scope: str = "scope",
    username: str = "root",
) -> BasicServerConfig:
    return BasicServerConfig(
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


def storage_config_factory(
    defaults: BasicServerConfig,
    settings: Settings,
) -> Dict:
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
            "id_token",
            "none",
            "token",
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

    return StorageConfig(
        authorization_codes=[authorization_code],
        clients=[client],
        server_config=defaults,
        tokens=[token],
    )


def storage_factory(storage_config: StorageConfig) -> Storage:
    return Storage(config=storage_config)
