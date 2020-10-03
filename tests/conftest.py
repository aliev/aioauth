import time
from typing import Optional, Text, Type

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
from async_oauth2_provider.requests import Request
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
    class DB(DBBase):
        async def get_client(
            self, request: Request, client_id: str, client_secret: Optional[str] = None
        ) -> Optional[Client]:
            clients = storage.get("clients", [])

            for client in clients:
                if client.client_id == client_id:
                    return client

        async def create_token(self, request: Request, client: Client) -> Token:
            token = await super().create_token(request, client)
            storage["tokens"].append(token)
            return token

        async def get_token(self, request: Request, client_id: str) -> Optional[Token]:
            tokens = storage.get("tokens", [])
            for token in tokens:
                if (
                    request.post.token == token.access_token
                    and client_id == token.client_id
                ):
                    return token

        async def authenticate(self, request: Request) -> Optional[bool]:
            if (
                request.post.username == defaults.username
                and request.post.password == defaults.password
            ):
                return True

        async def create_authorization_code(
            self, request: Request, client: Client
        ) -> AuthorizationCode:
            authorization_code = await super().create_authorization_code(
                request, client
            )
            storage["authorization_codes"].append(authorization_code)
            return authorization_code

        async def get_authorization_code(
            self, request: Request, client: Client
        ) -> Optional[AuthorizationCode]:
            authorization_codes = storage.get("authorization_codes", [])
            for authorization_code in authorization_codes:
                if (
                    authorization_code.code == request.post.code
                    and authorization_code.client_id == client.client_id
                ):
                    return authorization_code

        async def delete_authorization_code(
            self,
            request: Request,
            authorization_code: AuthorizationCode,
            client: Client,
        ):
            authorization_codes = storage.get("authorization_codes", [])
            for authorization_code in authorization_codes:
                if (
                    authorization_code.client_id == client.client_id
                    and authorization_code.code == request.post.code
                ):
                    authorization_codes.remove(authorization_code)

    return DB


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
