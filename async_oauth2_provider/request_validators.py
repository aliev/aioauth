from typing import Optional
from async_oauth2_provider.models import (
    AuthorizationCode,
    Client,
    Token,
)

from async_oauth2_provider.requests import Request


class BaseRequestValidator:
    def __init__(self, request: Request):
        self.request = request

    async def get_client(
        self, client_id: str, client_secret: Optional[str] = None, client=None
    ) -> Client:
        return Client.from_orm(client)

    async def create_token(self, client_id: str, token=None) -> Token:
        return Token.from_orm(token)

    async def get_user(self, username: str, password: str):
        ...

    async def create_authorization_code(
        self, client_id: str, authorization_code=None
    ) -> AuthorizationCode:
        return AuthorizationCode.from_orm(authorization_code)

    async def get_authorization_code(
        self, code: str, client_id: str, client_secret: str, authorization_code=None
    ) -> AuthorizationCode:
        return AuthorizationCode.from_orm(authorization_code)

    async def delete_authorization_code(self, code, client_id: str, client_secret: str):
        ...

    async def get_refresh_token(
        self, refresh_token: str, client_id: str, token=None
    ) -> Token:
        return Token.from_orm(token)

    async def revoke_token(self, refresh_token: str, client_id: str):
        ...
