import time
from async_oauth2_provider.types import GrantType, ResponseType
from async_oauth2_provider.grant_type import AuthorizationCodeGrantType
from async_oauth2_provider.models import (
    AuthorizationCodeModel,
    ClientModel,
    TokenModel,
    UserModel,
)
from async_oauth2_provider.request_validators import AuthorizationCodeRequestValidator, BaseRequestValidator
from async_oauth2_provider.requests import Post, Request
import pytest


class RequestValidator(BaseRequestValidator):
    async def get_client(self, client_id: str, client_secret: str) -> ClientModel:
        return ClientModel(
            client_id=client_id,
            client_secret=client_secret,
            client_metadata={"grant_types": [GrantType.TYPE_AUTHORIZATION_CODE.value]},
        )

    async def create_token(self) -> TokenModel:
        raise NotImplementedError()

    async def get_authorization_code(self, code: str) -> AuthorizationCodeModel:
        return AuthorizationCodeModel(
            code=code,
            client_id=self.request.client_id,
            redirect_uri="https://google.com",
            response_type=ResponseType.TYPE_TOKEN,
            scope="",
            auth_time=time.time(),
            code_challenge="123",
            code_challenge_method="RS256",
        )

    async def delete_authorization_code(self, code):
        pass

    async def get_user(
        self, request: Request, username: str, password: str
    ) -> UserModel:
        raise NotImplementedError()

    async def get_refresh_token(
        self, request: Request, refresh_token: str
    ) -> TokenModel:
        raise NotImplementedError()

    async def revoke_token(self, request: Request, refresh_token: str):
        raise NotImplementedError()



class AuthorizationCodeRequestValidatorBase(AuthorizationCodeRequestValidator):
    async def get_client(self, client_id: str, client_secret: str) -> ClientModel:
        import pdb; pdb.set_trace()

    async def create_token(self) -> TokenModel:
        raise NotImplementedError()

    async def get_authorization_code(self, code: str) -> AuthorizationCodeModel:
        raise NotImplementedError()

    async def delete_authorization_code(self, code):
        raise NotImplementedError()


@pytest.mark.asyncio
async def test_authroization_code_grant_type():
    request = Request(
        url="https://google.com/",
        headers={
            "Authorization": "Basic YWRtaW46MTIz"
        },
        post=Post(
            grant_type="authorization_code"
        )
    )
    grant_type = AuthorizationCodeGrantType(request, AuthorizationCodeRequestValidatorBase)

    response = await grant_type.create_token_response()

    import pdb; pdb.set_trace()
