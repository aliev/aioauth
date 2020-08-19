from typing import Optional
from async_oauth2_provider.models import (
    AuthorizationCodeModel,
    ClientModel,
    TokenModel,
    UserModel,
)

from async_oauth2_provider.requests import Request


class BaseRequestValidator:
    request: Request

    def __init__(self, request: Request):
        self.request = request

    async def get_client(
        self, client_id: str, client_secret: Optional[str] = None
    ) -> ClientModel:
        raise NotImplementedError()

    async def create_token(self, client_id: str) -> TokenModel:
        raise NotImplementedError()

    async def get_user(self, username: str, password: str) -> UserModel:
        # NOTE: Rename to get_user_id
        raise NotImplementedError()

    async def create_authorization_code(self, client_id: str) -> AuthorizationCodeModel:
        raise NotImplementedError()


class AuthorizationCodeRequestValidator(BaseRequestValidator):
    async def get_authorization_code(
        self, code: str, client_id: str, client_secret: str
    ) -> AuthorizationCodeModel:
        raise NotImplementedError()

    async def delete_authorization_code(self, code, client_id: str, client_secret: str):
        raise NotImplementedError()


class PasswordRequestValidator(BaseRequestValidator):
    async def get_user(self, username: str, password: str) -> UserModel:
        raise NotImplementedError()


class RefreshTokenRequestValidator(BaseRequestValidator):
    async def get_refresh_token(self, refresh_token: str, client_id: str) -> TokenModel:
        raise NotImplementedError()

    async def revoke_token(self, refresh_token: str, client_id: str):
        raise NotImplementedError()
