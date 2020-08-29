from time import time
from typing import Optional
from async_oauth2_provider.types import GrantType, ResponseType
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.config import settings


CLIENT_ID = "1234"
CLIENT_SECRET = "12345"
CODE = "some random code"
REFRESH_TOKEN = "some random refresh token"
ACCESS_TOKEN = "some random access token"
REDIRECT_URI = "https://ownauth.com/callback"

def get_client():
    return Client(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        client_metadata={
            "grant_types": [
                GrantType.TYPE_AUTHORIZATION_CODE.value,
                GrantType.TYPE_CLIENT_CREDENTIALS.value,
                GrantType.TYPE_REFRESH_TOKEN.value,
                GrantType.TYPE_PASSWORD
            ],
            "redirect_uris": [REDIRECT_URI],
            "response_types": ["code", "token"]
        },
    )


def get_authorization_code():
    return AuthorizationCode(
        code=CODE,
        client_id=CLIENT_ID,
        response_type="code",
        auth_time=time.time(),
        redirect_uri=REDIRECT_URI
    )


def get_refresh_token():
    return Token(
        client_id=CLIENT_ID,
        expires_in=settings.TOKEN_EXPIRES_IN,
        access_token=ACCESS_TOKEN,
        refresh_token=REFRESH_TOKEN,
        issued_at=time.time(),
        scope="",
    )


class DB(DBBase):
    async def delete_authorization_code(self, code, client_id: str): ...
    async def revoke_token(self, refresh_token: str, client_id: str): ...

    async def create_authorization_code(self, client_id: str, scope: str, response_type: ResponseType) -> AuthorizationCode:
        authorization_code = await super().create_authorization_code(client_id, scope, response_type)
        # Save authorization code in DB here
        return authorization_code

    async def create_token(self, client_id: str, scope: str) -> Token:
        token = await super().create_token(client_id, scope)
        # Save token in DB here
        return token

    async def get_client(self, client_id: str, client_secret: Optional[str] = None) -> Optional[Client]:
        if client_id == CLIENT_ID:
            return get_client()

    async def get_user(self, username: str, password: str):
        if username == "admin" and password == "admin":
            return True

    async def get_authorization_code(self, code: str, client_id: str) -> Optional[AuthorizationCode]:
        if code == CODE and client_id == CLIENT_ID:
            return get_authorization_code()

    async def get_refresh_token(self, refresh_token: str, client_id: str) -> Optional[Token]:
        if client_id == CLIENT_ID and refresh_token == REFRESH_TOKEN:
            return get_refresh_token()
