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
        self, client_id: str, client_secret: Optional[str] = None
    ) -> Client:
        raise NotImplementedError()

    async def create_token(self, client_id: str) -> Token:
        raise NotImplementedError()

    async def get_user(self, username: str, password: str):
        raise NotImplementedError()

    async def create_authorization_code(self, client_id: str) -> AuthorizationCode:
        raise NotImplementedError()

    async def get_authorization_code(
        self, code: str, client_id: str, client_secret: str
    ) -> AuthorizationCode:
        raise NotImplementedError()

    async def delete_authorization_code(self, code, client_id: str, client_secret: str):
        raise NotImplementedError()

    async def get_refresh_token(self, refresh_token: str, client_id: str) -> Token:
        raise NotImplementedError()

    async def revoke_token(self, refresh_token: str, client_id: str):
        raise NotImplementedError()
