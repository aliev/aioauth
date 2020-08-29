import time
from async_oauth2_provider.types import GrantType, ResponseType
from async_oauth2_provider.config import settings
from authlib.common.security import generate_token
from async_oauth2_provider.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType, GrantTypeBase,
    RefreshTokenGrantType,
)
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.models import (
    AuthorizationCode,
    Client,
    Token,
)
from async_oauth2_provider.request_validators import BaseRequestValidator
from async_oauth2_provider.requests import Post, Query, Request
import pytest


class RequestValidator(BaseRequestValidator):
    async def get_client(self, client_id: str, client_secret: str = "") -> Client:
        return Client(
            client_id=client_id,
            client_secret=client_secret,
            client_metadata={
                "grant_types": [
                    GrantType.TYPE_AUTHORIZATION_CODE.value,
                    GrantType.TYPE_CLIENT_CREDENTIALS.value,
                    GrantType.TYPE_REFRESH_TOKEN.value,
                ],
                "redirect_uris": ["https://google.com"],
                "response_types": ["code", "token"]
            },
        )

    async def create_token(self, client_id: str) -> Token:
        return Token(
            client_id=client_id,
            expires_in=settings.TOKEN_EXPIRES_IN,
            access_token=generate_token(42),
            refresh_token=generate_token(48),
            issued_at=time.time(),
            scope="",
            revoked=False,
        )

    async def get_authorization_code(
        self, code: str, client_id: str, client_secret: str
    ) -> AuthorizationCode:
        return AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri="https://google.com",
            response_type=ResponseType.TYPE_TOKEN,
            scope="",
            auth_time=time.time(),
            code_challenge="123",
            code_challenge_method="RS256",
        )

    async def create_authorization_code(self, client_id: str) -> AuthorizationCode:
        return AuthorizationCode(
            code="12333",
            client_id=client_id,
            redirect_uri="https://google.com",
            response_type=ResponseType.TYPE_TOKEN,
            scope="",
            auth_time=time.time(),
            code_challenge="123",
            code_challenge_method="RS256",
        )

    async def delete_authorization_code(
        self, code: str, client_id: str, client_secret: str
    ):
        pass

    async def get_user(self, username: str, password: str):
        return True

    async def get_refresh_token(self, refresh_token: str, client_id: str) -> Token:
        return Token(
            client_id=client_id,
            expires_in=settings.TOKEN_EXPIRES_IN,
            access_token=generate_token(42),
            refresh_token=generate_token(48),
            issued_at=time.time(),
            scope="",
            revoked=False,
        )

    async def revoke_token(self, refresh_token: str, client_id: str):
        pass


@pytest.mark.asyncio
async def test_authroization_code_grant_type():
    request = Request(
        url="https://google.com/",
        # headers={"Authorization": "Basic YWRtaW46MTIz"},
        post=Post(username="admin", password="admin"),
        query=Query(client_id="123", response_type="code", redirect_uri="https://google.com", scope="hello", state="test"),
        method="POST"
    )

    token_endpoint = OAuth2Endpoint(
        request_validator_cls=RequestValidator,
    )

    response = await token_endpoint.create_authorization_response(request)
    import pdb; pdb.set_trace()
