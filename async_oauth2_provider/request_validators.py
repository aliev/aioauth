from async_oauth2_provider.models import (
    AuthorizationCodeModel,
    ClientModel,
    TokenModel,
    UserModel,
)

from async_oauth2_provider.requests import Request


class BaseRequestValidator:
    async def get_client(
        self, request: Request, client_id: str, client_secret: str
    ) -> ClientModel:
        raise NotImplementedError()

    async def create_token(self, request: Request) -> TokenModel:
        raise NotImplementedError()


class AuthorizationCodeRequestValidator(BaseRequestValidator):
    async def get_authorization_code(
        self, request: Request, code: str
    ) -> AuthorizationCodeModel:
        raise NotImplementedError()

    async def delete_authorization_code(self, request: Request, code):
        raise NotImplementedError()


class PasswordRequestValidator(BaseRequestValidator):
    async def get_user(
        self, request: Request, username: str, password: str
    ) -> UserModel:
        raise NotImplementedError()


class RefreshTokenRequestValidator(BaseRequestValidator):
    async def get_refresh_token(
        self, request: Request, refresh_token: str
    ) -> TokenModel:
        raise NotImplementedError()

    async def revoke_token(self, request: Request, refresh_token: str):
        raise NotImplementedError()
