import time
from typing import Optional, Text, Type

import pytest
from async_oauth2_provider.config import settings
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.grant_type import AuthorizationCodeGrantType
from async_oauth2_provider.models import (
    AuthorizationCode,
    Client,
    ClientMetadata,
    Token,
)
from async_oauth2_provider.requests import Request
from async_oauth2_provider.response_type import ResponseTypeToken
from async_oauth2_provider.types import (
    CodeChallengeMethod,
    EndpointType,
    GrantType,
    ResponseType,
)
from async_oauth2_provider.utils import generate_token
from pydantic import BaseModel
from pydantic.networks import AnyHttpUrl


class Defaults(BaseModel):
    client_id: Text
    client_secret: Text
    code: Text
    refresh_token: Text
    access_token: Text
    username: Text
    password: Text
    redirect_uri: AnyHttpUrl
    scope: Text


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
def client_metadata(defaults: Defaults) -> ClientMetadata:
    return ClientMetadata(
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


@pytest.fixture
def client(defaults: Defaults, client_metadata: ClientMetadata) -> Client:
    return Client(
        client_id=defaults.client_id,
        client_secret=defaults.client_secret,
        client_metadata=client_metadata,
    )


@pytest.fixture
def authorization_code(defaults: Defaults) -> AuthorizationCode:
    return AuthorizationCode(
        code=defaults.code,
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        auth_time=time.time(),
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        code_challenge_method=CodeChallengeMethod.PLAIN,
    )


@pytest.fixture
def token(defaults: Defaults) -> Token:
    return Token(
        client_id=defaults.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
        access_token=defaults.access_token,
        refresh_token=defaults.refresh_token,
        issued_at=time.time(),
        scope=defaults.scope,
    )


@pytest.fixture
def db_class(
    defaults: Defaults,
    client: Client,
    authorization_code: AuthorizationCode,
    token: Token,
) -> Type[DBBase]:
    class DB(DBBase):
        async def delete_authorization_code(
            self, request: Request, authorization_code: AuthorizationCode
        ):
            ...

        async def revoke_token(self, request: Request, token: Token):
            ...

        async def get_client(
            self, request: Request, client_id: str, client_secret: Optional[str] = None
        ) -> Optional[Client]:
            if client_id == defaults.client_id:
                return client

        async def get_user(self, request: Request) -> Optional[bool]:
            if (
                request.post.username == defaults.username
                and request.post.password == defaults.password
            ):
                return True

        async def get_authorization_code(
            self, request: Request, client: Client
        ) -> Optional[AuthorizationCode]:
            if (
                request.post.code == defaults.code
                and client.client_id == defaults.client_id
            ):
                return authorization_code

        async def get_refresh_token(
            self, request: Request, client: Client
        ) -> Optional[Token]:
            if (
                client.client_id == defaults.client_id
                and request.post.refresh_token == defaults.refresh_token
            ):
                return token

    return DB


@pytest.fixture
def endpoint(db_class: Type[DBBase]) -> OAuth2Endpoint:
    endpoint = OAuth2Endpoint(db=db_class())
    endpoint.register(
        EndpointType.RESPONSE_TYPE, ResponseType.TYPE_TOKEN, ResponseTypeToken
    )
    endpoint.register(
        EndpointType.GRANT_TYPE,
        GrantType.TYPE_AUTHORIZATION_CODE,
        AuthorizationCodeGrantType,
    )
    return endpoint
