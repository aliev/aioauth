from typing import Optional

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.grant_type import AuthorizationCodeGrantType
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request as OAuth2Request
from async_oauth2_provider.response_type import ResponseTypeToken
from async_oauth2_provider.types import EndpointType, GrantType, ResponseType
from fastapi_oauth2.tables import AuthorizationCodeTable, ClientTable, TokenTable


class PostgreSQL(DBBase):
    async def create_token(self, request: OAuth2Request, client: Client) -> Token:
        token = await super().create_token(request, client)
        await TokenTable(**token.dict()).query.create()
        return token

    async def create_authorization_code(
        self, request: OAuth2Request, client: Client
    ) -> AuthorizationCode:
        authorization_code = await super().create_authorization_code(request, client)
        await AuthorizationCodeTable(**authorization_code.dict()).create()
        return authorization_code

    async def get_client(
        self, request: OAuth2Request, client_id: str, client_secret: Optional[str]
    ) -> Optional[Client]:
        query = ClientTable.query.where(ClientTable.client_id == client_id)
        if client_secret is not None:
            query = query.where(ClientTable.client_secret == client_secret)

        record = await query.gino.first()

        if record is not None:
            return Client.from_orm(record)

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
