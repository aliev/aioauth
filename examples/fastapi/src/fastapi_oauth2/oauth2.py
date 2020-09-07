from typing import Optional

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.grant_type import AuthorizationCodeGrantType
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request as OAuth2Request
from async_oauth2_provider.response_type import ResponseTypeToken
from async_oauth2_provider.types import EndpointType, GrantType, ResponseType


class PostgreSQL(DBBase):
    async def create_token(self, request: OAuth2Request, client: Client) -> Token:
        token = await super().create_token(request, client)
        return token

    async def create_authorization_code(
        self, request: OAuth2Request, client: Client
    ) -> AuthorizationCode:
        authorization_code = await super().create_authorization_code(request, client)
        return authorization_code

    async def get_client(
        self, request: OAuth2Request, client_id: str, client_secret: Optional[str]
    ) -> Optional[Client]:
        ...

    async def get_user(self, request: OAuth2Request) -> bool:
        ...

    async def delete_authorization_code(
        self, request: OAuth2Request, authorization_code: AuthorizationCode
    ):
        ...


endpoint = OAuth2Endpoint(PostgreSQL())

endpoint.register(
    EndpointType.RESPONSE_TYPE, ResponseType.TYPE_TOKEN, ResponseTypeToken
)
endpoint.register(
    EndpointType.GRANT_TYPE,
    GrantType.TYPE_AUTHORIZATION_CODE,
    AuthorizationCodeGrantType,
)
