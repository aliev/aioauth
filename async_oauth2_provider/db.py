import time
from typing import Optional

from async_oauth2_provider.config import settings
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request
from async_oauth2_provider.types import CodeChallengeMethod, ResponseType
from authlib.common.security import generate_token


class DBBase:
    def __init__(self, request: Request):
        self.request = request

    async def create_token(self, client_id: str, scope: str) -> Token:
        return Token(
            client_id=client_id,
            expires_in=settings.TOKEN_EXPIRES_IN,
            access_token=generate_token(42),
            refresh_token=generate_token(48),
            issued_at=time.time(),
            scope=scope,
            revoked=False,
        )

    async def create_authorization_code(
        self,
        client_id: str,
        scope: str,
        response_type: ResponseType,
        state: Optional[str] = "",
    ) -> AuthorizationCode:
        code = generate_token(48)

        return AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=self.request.query.redirect_uri,
            response_type=response_type,
            scope=scope,
            auth_time=time.time(),
            code_challenge_method=CodeChallengeMethod.PLAIN,
            state=state,
        )

    async def get_client(
        self, client_id: str, client_secret: Optional[str] = None
    ) -> Client:
        raise NotImplementedError()

    async def get_user(self, username: str, password: str):
        raise NotImplementedError()

    async def get_authorization_code(
        self, code: str, client_id: str
    ) -> Optional[AuthorizationCode]:
        raise NotImplementedError()

    async def delete_authorization_code(self, code, client_id: str):
        raise NotImplementedError()

    async def get_refresh_token(self, refresh_token: str, client_id: str) -> Token:
        raise NotImplementedError()

    async def revoke_token(self, refresh_token: str, client_id: str):
        raise NotImplementedError()
