from typing import Optional

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request as OAuth2Request
from async_oauth2_provider.response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeToken,
)
from async_oauth2_provider.types import EndpointType, GrantType, ResponseType
from fastapi_oauth2.tables import AuthorizationCodeTable, ClientTable, TokenTable


class PostgreSQL(DBBase):
    async def create_token(self, request: OAuth2Request, client: Client) -> Token:
        token = await super().create_token(request, client)
        await TokenTable(
            client_id=token.client_id,
            token_type=token.token_type,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            issued_at=token.issued_at,
            expires_in=token.expires_in,
        ).create()
        return token

    async def create_authorization_code(
        self, request: OAuth2Request, client: Client
    ) -> AuthorizationCode:
        authorization_code = await super().create_authorization_code(request, client)

        # Create authorization code record
        await AuthorizationCodeTable(
            code=authorization_code.code,
            client_id=authorization_code.client_id,
            redirect_uri=str(authorization_code.redirect_uri),
            response_type=authorization_code.response_type.value,
            scope=authorization_code.scope,
            nonce=authorization_code.nonce,
            code_challenge=authorization_code.code_challenge,
            code_challenge_method=authorization_code.code_challenge_method.value,
            auth_time=authorization_code.auth_time,
        ).create()

        return authorization_code

    async def get_authorization_code(
        self, request: OAuth2Request, client: Client
    ) -> Optional[AuthorizationCode]:
        authorization_code_record = (
            await AuthorizationCodeTable.query.where(
                AuthorizationCodeTable.code == request.post.code
            )
            .where(
                AuthorizationCodeTable.redirect_uri == str(request.post.redirect_uri)
            )
            .gino.first()
        )

        return AuthorizationCode.from_orm(authorization_code_record)

    async def get_client(
        self,
        request: OAuth2Request,
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> Optional[Client]:
        query = ClientTable.query.where(ClientTable.client_id == client_id)
        if client_secret is not None:
            query = query.where(ClientTable.client_secret == client_secret)

        record = await query.gino.first()

        if record is not None:
            return Client.from_orm(record)

    async def get_user(self, request: OAuth2Request) -> bool:
        if request.post.username == "admin" and request.post.password == "admin":
            return True

        return False

    async def delete_authorization_code(
        self, request: OAuth2Request, authorization_code: AuthorizationCode
    ):
        ...


postgres = PostgreSQL()
endpoint = OAuth2Endpoint(postgres)

# Register response type endpoints
endpoint.register(
    EndpointType.RESPONSE_TYPE, ResponseType.TYPE_TOKEN, ResponseTypeToken,
)
endpoint.register(
    EndpointType.RESPONSE_TYPE, ResponseType.TYPE_CODE, ResponseTypeAuthorizationCode,
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
