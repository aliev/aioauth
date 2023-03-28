import time
from typing import Dict, List, Optional

from aioauth.config import Settings
from aioauth.models import AuthorizationCode, Client, Token
from aioauth.types import GrantType, ResponseType
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


def client_factory(
    client_id: str = generate_token(42),
    client_secret: str = generate_token(48),
    grant_types: Optional[List[GrantType]] = None,
    redirect_uris: Optional[List[str]] = None,
    response_types: Optional[List[ResponseType]] = None,
    scope: str = "scope",
) -> Client:
    _redirect_uris = redirect_uris or ["https://ownauth.com/callback"]
    _response_types = response_types or ["code", "id_token", "none", "token"]
    _grant_types = grant_types or [
        "authorization_code",
        "client_credentials",
        "password",
        "refresh_token",
    ]
    return Client(
        client_id=client_id,
        client_secret=client_secret,
        grant_types=_grant_types,
        redirect_uris=_redirect_uris,
        response_types=_response_types,
        scope=scope,
    )


def storage_config_factory(
    defaults: BasicServerConfig,
    settings: Settings,
) -> Dict:
    client = client_factory(
        client_id=defaults.client_id,
        client_secret=defaults.client_secret,
        redirect_uris=[defaults.redirect_uri],
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
    server_config = storage_config.server_config
    client = client_factory(
        client_id=server_config.client_id,
        client_secret=server_config.client_secret,
        redirect_uris=[server_config.redirect_uri],
        scope=server_config.scope,
    )

    return Storage(
        authorization_codes=storage_config.authorization_codes,
        clients=[client],
        tokens=storage_config.tokens,
        users={server_config.username: server_config.password},
    )
