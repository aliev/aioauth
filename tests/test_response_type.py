from typing import Optional
import time

from async_oauth2_provider.requests import Post, Query, Request
from async_oauth2_provider.models import AuthorizationCodeModel, ClientModel, TokenModel, UserModel
from async_oauth2_provider.request_validators import BaseRequestValidator
from async_oauth2_provider.types import GrantType, RequestMethod, ResponseType
from async_oauth2_provider.endpoints import ResponseTypeEndpoint
from async_oauth2_provider.response_type import ResponseTypeToken, ResponseTypeAuthorizationCode
import pytest


class RequestValidatorClass(BaseRequestValidator):
    async def get_client(
        self, client_id: str, client_secret: Optional[str] = None
    ) -> ClientModel:
        return ClientModel(
            client_id=client_id,
            client_secret="123",
            client_metadata={
                "grant_types": [
                    GrantType.TYPE_AUTHORIZATION_CODE.value,
                    GrantType.TYPE_CLIENT_CREDENTIALS.value,
                    GrantType.TYPE_REFRESH_TOKEN.value,
                ],
                "redirect_uris": ["https://ownauth.com/callback"],
                "response_types": ["code", "token"]
            },
        )

    async def create_token(self, client_id: str) -> TokenModel:
        raise NotImplementedError()

    async def get_user(self, username: str, password: str) -> UserModel:
        # NOTE: Rename to get_user_id
        return 1

    async def create_authorization_code(self, client_id: str) -> AuthorizationCodeModel:
        return AuthorizationCodeModel(
            code="123",
            client_id=client_id,
            redirect_uri="https://google.com",
            response_type=ResponseType.TYPE_TOKEN,
            scope="",
            auth_time=time.time(),
            code_challenge="123",
            code_challenge_method="RS256",
        )


@pytest.mark.asyncio
async def test_response_type():
    query = Query(
        client_id="123",
        response_type=ResponseType.TYPE_CODE,
        redirect_uri="https://ownauth.com/callback",
        scope="asd",
        state="ssss"
    )

    post = Post(
        username="admin",
        password="admin"
    )
    request = Request(url="https://google.com", query=query, method=RequestMethod.POST, post=post)
    response_type_endpoint = ResponseTypeEndpoint(
        {
            ResponseType.TYPE_CODE: ResponseTypeAuthorizationCode,
            ResponseType.TYPE_TOKEN: ResponseTypeToken
        },
        RequestValidatorClass,
    )

    response = await response_type_endpoint.create_authorization_response(request)
