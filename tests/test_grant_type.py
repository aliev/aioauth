import time
from async_oauth2_provider.types import GrantType, ResponseType
from async_oauth2_provider.config import settings
from authlib.common.security import generate_token
from async_oauth2_provider.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType, GrantTypeBase,
    RefreshTokenGrantType,
)
from async_oauth2_provider.endpoints import TokenEndpoint
from async_oauth2_provider.models import (
    AuthorizationCodeModel,
    ClientModel,
    TokenModel,
    UserModel,
)
from async_oauth2_provider.request_validators import BaseRequestValidator
from async_oauth2_provider.requests import Post, Request
import pytest


class RequestValidator(BaseRequestValidator):
    async def get_client(self, client_id: str, client_secret: str) -> ClientModel:
        return ClientModel(
            client_id=client_id,
            client_secret=client_secret,
            client_metadata={
                "grant_types": [
                    GrantType.TYPE_AUTHORIZATION_CODE.value,
                    GrantType.TYPE_CLIENT_CREDENTIALS.value,
                    GrantType.TYPE_REFRESH_TOKEN.value,
                ]
            },
        )

    async def create_token(self, client_id: str) -> TokenModel:
        return TokenModel(
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
    ) -> AuthorizationCodeModel:
        return AuthorizationCodeModel(
            code=code,
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

    async def get_user(self, username: str, password: str) -> UserModel:
        raise NotImplementedError()

    async def get_refresh_token(self, refresh_token: str, client_id: str) -> TokenModel:
        return TokenModel(
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
        headers={"Authorization": "Basic YWRtaW46MTIz"},
        post=Post(grant_type="refresh_token", code="123", refresh_token="111",),
    )

    token_endpoint = TokenEndpoint(
        default_grant_type=GrantTypeBase,
        grant_types={
            GrantType.TYPE_AUTHORIZATION_CODE: AuthorizationCodeGrantType,
            GrantType.TYPE_CLIENT_CREDENTIALS: ClientCredentialsGrantType,
            GrantType.TYPE_REFRESH_TOKEN: RefreshTokenGrantType,
        },
        request_validator_class=RequestValidator,
    )

    response = await token_endpoint.create_token_response(request)
