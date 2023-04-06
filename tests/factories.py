import time
from typing import Dict, List, Optional

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
from aioauth.types import GrantType, ResponseType
from aioauth.utils import generate_token

from tests.classes import AuthorizationContext, Storage


def access_token_factory() -> str:
    return generate_token(42)


def refresh_token_factory() -> str:
    return generate_token(48)


def client_id_factory() -> str:
    return generate_token(48)


def client_secret_factory() -> str:
    return generate_token(48)


def authorization_code_factory() -> str:
    return generate_token(5)


def auth_time_factory() -> int:
    return int(time.time())


def grant_types_factory() -> Dict[str, GrantType]:
    return {
        "authorization_code": AuthorizationCodeGrantType[Request, Storage],
        "client_credentials": ClientCredentialsGrantType[Request, Storage],
        "password": PasswordGrantType[Request, Storage],
        "refresh_token": RefreshTokenGrantType[Request, Storage],
    }


def response_types_factory() -> Dict[str, ResponseType]:
    return {
        "code": ResponseTypeAuthorizationCode[Request, Storage],
        "id_token": ResponseTypeIdToken[Request, Storage],
        "none": ResponseTypeNone[Request, Storage],
        "token": ResponseTypeToken[Request, Storage],
    }


def settings_factory() -> Settings:
    return Settings(INSECURE_TRANSPORT=True)


def client_factory(
    client_id: str = client_id_factory(),
    client_secret: str = client_secret_factory(),
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


def authorization_code_factory(
    auth_time: int = auth_time_factory(),
    client_id: str = client_id_factory(),
    code: str = authorization_code_factory(),
    code_challenge_method: str = "plain",
    expires_in: int = 10,
    redirect_uri: str = "http://redirect.uri",
    response_type: str = "code",
    scope: str = "scope",
) -> AuthorizationCode:
    return AuthorizationCode(
        auth_time=auth_time,
        client_id=client_id,
        code=code,
        code_challenge_method=code_challenge_method,
        expires_in=expires_in,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scope,
    )


def token_factory(
    access_token: str = access_token_factory(),
    client_id: str = client_id_factory(),
    expires_in: int = 300,
    issued_at: int = auth_time_factory(),
    refresh_token: str = refresh_token_factory(),
    refresh_token_expires_in: int = 600,
    scope: str = "scope",
) -> Token:
    return Token(
        access_token=access_token,
        client_id=client_id,
        expires_in=expires_in,
        issued_at=issued_at,
        refresh_token=refresh_token,
        refresh_token_expires_in=refresh_token_expires_in,
        scope=scope,
    )


def context_factory(
    clients: Optional[List[Client]] = None,
    grant_types: Optional[Dict[str, GrantType]] = None,
    initial_authorization_codes: Optional[List[AuthorizationCode]] = None,
    initial_tokens: Optional[List[Token]] = None,
    response_types: Optional[Dict[str, ResponseType]] = None,
    settings: Optional[Settings] = None,
    users: Optional[Dict[str, str]] = None,
) -> AuthorizationContext:
    _clients = clients or [
        client_factory(),
        client_factory(),
    ]
    _initial_authorization_codes = initial_authorization_codes or [
        authorization_code_factory(
            client_id=client.client_id,
            redirect_uri=client.redirect_uris if client.redirect_uris else "",
            scope=client.scope,
        )
        for client in _clients
    ]
    _initial_tokens = initial_tokens or [
        token_factory(
            client_id=client.client_id,
            scope=client.scope,
        )
        for client in _clients
    ]
    _grant_types = grant_types or grant_types_factory()
    _response_types = response_types or response_types_factory()
    _settings = settings or settings_factory()
    _users = users or {"root": "toor"}
    return AuthorizationContext(
        clients=_clients,
        initial_authorization_codes=_initial_authorization_codes,
        initial_tokens=_initial_tokens,
        grant_types=_grant_types,
        response_types=_response_types,
        settings=_settings,
        users=_users,
    )
