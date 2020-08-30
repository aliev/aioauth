import time
from typing import Optional

import pytest
from async_oauth2_provider.config import settings
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.types import CodeChallengeMethod, GrantType, ResponseType
from endpoints import OAuth2Endpoint


@pytest.fixture
def defaults():
    return {
        "client_id": "random client id",
        "client_secret": "random client secret",
        "code": "random code",
        "refresh_token": "random refresh token",
        "access_token": "random access token",
        "username": "admin",
        "password": "admin",
        "redirect_uri": "https://ownauth.com/callback",
    }


@pytest.fixture
def client(defaults):
    return Client(
        client_id=defaults["client_id"],
        client_secret=defaults["client_secret"],
        client_metadata={
            "grant_types": [
                GrantType.TYPE_AUTHORIZATION_CODE.value,
                GrantType.TYPE_CLIENT_CREDENTIALS.value,
                GrantType.TYPE_REFRESH_TOKEN.value,
                GrantType.TYPE_PASSWORD,
            ],
            "redirect_uris": [defaults["redirect_uri"]],
            "response_types": ["code", "token"],
        },
    )


@pytest.fixture
def authorization_code(defaults):
    return AuthorizationCode(
        code=defaults["code"],
        client_id=defaults["client_id"],
        response_type="code",
        auth_time=time.time(),
        redirect_uri=defaults["redirect_uri"],
        scope="",
        code_challenge_method=CodeChallengeMethod.PLAIN,
    )


@pytest.fixture
def token(defaults):
    return Token(
        client_id=defaults["client_id"],
        expires_in=settings.TOKEN_EXPIRES_IN,
        access_token=defaults["access_token"],
        refresh_token=defaults["refresh_token"],
        issued_at=time.time(),
        scope="",
    )


@pytest.fixture
def db_class(defaults, client, authorization_code, token):
    class DB(DBBase):
        async def delete_authorization_code(self, code, client_id: str):
            ...

        async def revoke_token(self, refresh_token: str, client_id: str):
            ...

        async def create_authorization_code(
            self, client_id: str, scope: str, response_type: ResponseType
        ) -> AuthorizationCode:
            authorization_code = await super().create_authorization_code(
                client_id, scope, response_type
            )
            # Save authorization code in DB here
            return authorization_code

        async def create_token(self, client_id: str, scope: str) -> Token:
            token = await super().create_token(client_id, scope)
            # Save token in DB here
            return token

        async def get_client(
            self, client_id: str, client_secret: Optional[str] = None
        ) -> Optional[Client]:
            if client_id == defaults["client_id"]:
                return client

        async def get_user(self, username: str, password: str):
            if username == defaults["username"] and password == defaults["password"]:
                return True

        async def get_authorization_code(
            self, code: str, client_id: str
        ) -> Optional[AuthorizationCode]:
            if code == defaults["code"] and client_id == defaults["client_id"]:
                return authorization_code

        async def get_refresh_token(
            self, refresh_token: str, client_id: str
        ) -> Optional[Token]:
            if (
                client_id == defaults["client_id"]
                and refresh_token == defaults["refresh_token"]
            ):
                return token

    return DB


@pytest.fixture
def endpoint(db_class):
    return OAuth2Endpoint(db_class=db_class)
