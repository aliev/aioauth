import time
from typing import Optional

from async_oauth2_provider.config import settings
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request
from async_oauth2_provider.types import CodeChallengeMethod
from authlib.common.security import generate_token


class DBBase:
    def __init__(self, request: Request):
        self.request = request

    async def create_token(self, client: Client) -> Token:
        return Token(
            client_id=client.client_id,
            expires_in=settings.TOKEN_EXPIRES_IN,
            access_token=generate_token(42),
            refresh_token=generate_token(48),
            issued_at=time.time(),
            scope=client.get_allowed_scope(self.request.post.scope),
            revoked=False,
        )

    async def create_authorization_code(self, client: Client,) -> AuthorizationCode:
        return AuthorizationCode(
            code=generate_token(48),
            client_id=client.client_id,
            redirect_uri=self.request.query.redirect_uri,
            response_type=self.request.query.response_type,
            scope=client.get_allowed_scope(self.request.post.scope),
            auth_time=time.time(),
            code_challenge_method=CodeChallengeMethod.PLAIN,
            state=self.request.query.state,
        )

    async def get_client(
        self, client_id: str, client_secret: Optional[str] = None
    ) -> Client:
        raise NotImplementedError()

    async def get_user(self):
        raise NotImplementedError()

    async def get_authorization_code(
        self, client: Client
    ) -> Optional[AuthorizationCode]:
        raise NotImplementedError()

    async def delete_authorization_code(self, authorization_code: AuthorizationCode):
        raise NotImplementedError()

    async def get_refresh_token(self, client: Client) -> Optional[Token]:
        raise NotImplementedError()

    async def revoke_token(self, token: Token):
        raise NotImplementedError()
