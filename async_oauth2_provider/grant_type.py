import binascii
from base64 import b64decode
from typing import Type

from models import ClientModel, TokenModel

from async_oauth2_provider.utils import (
    get_authorization_scheme_param,
    is_secure_transport,
)

from async_oauth2_provider.exceptions import (
    AuthorizationCodeExpiredException,
    HTTPMethodNotAllowed,
    InsecureTransportError,
    InvalidAuthorizationCodeException,
    InvalidCredentialsException,
    InvalidRedirectUri,
    MissingAuthorizationCodeException,
    InvalidGrantTypeException,
    InvalidRefreshTokenException,
    InvalidUsernameOrPasswordException,
    MissingGrantTypeException,
    InvalidClientException,
    MissingPasswordException,
    MissingRedirectUri,
    MissingRefreshTokenException,
    MissingUsernameException,
    RefreshTokenExpiredException,
)

from async_oauth2_provider.types import GrantType, RequestMethod
from async_oauth2_provider.requests import Request
from async_oauth2_provider.request_validators import BaseRequestValidator


class GrantTypeBase:
    grant_type: GrantType
    allowed_methods = (
        RequestMethod.GET,
        RequestMethod.POST,
    )

    def __init__(
        self,
        request_validator_class: Type[BaseRequestValidator] = BaseRequestValidator,
    ):
        self.request_validator_class = request_validator_class

    async def create_token(self, request: Request) -> TokenModel:
        request_validator = self.get_request_validator(request)
        client = await self.validate_request(request, request_validator)
        return await request_validator.create_token(client.client_id)

    def get_request_validator(self, request: Request):
        return self.request_validator_class(request)

    async def validate_request(
        self, request: Request, request_validator: BaseRequestValidator
    ) -> ClientModel:
        authorization: str = request.headers.get("Authorization", "")
        scheme, param = get_authorization_scheme_param(authorization)

        if not is_secure_transport(request.url):
            raise InsecureTransportError()

        if request.method not in self.allowed_methods:
            raise HTTPMethodNotAllowed()

        if not authorization or scheme.lower() != "basic":
            raise InvalidCredentialsException()

        try:
            data = b64decode(param).decode("ascii")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            raise InvalidCredentialsException()

        client_id, separator, client_secret = data.partition(":")

        if not separator:
            raise InvalidCredentialsException()

        if not request.post.grant_type:
            raise MissingGrantTypeException()

        if self.grant_type != request.post.grant_type:
            raise InvalidGrantTypeException()

        client = await request_validator.get_client(
            client_id=client_id, client_secret=client_secret
        )

        if not client:
            raise InvalidClientException()

        if not client.check_grant_type(request.post.grant_type.value):
            raise InvalidGrantTypeException()

        return client


class AuthorizationCodeGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_AUTHORIZATION_CODE

    async def validate_request(
        self, request: Request, request_validator: BaseRequestValidator
    ) -> ClientModel:
        client = await super().validate_request(request, request_validator)

        if not request.post.redirect_uri:
            raise MissingRedirectUri()

        if not client.check_redirect_uri(request.post.redirect_uri):
            raise InvalidRedirectUri()

        if not request.post.code:
            raise MissingAuthorizationCodeException()

        authorization_code = await request_validator.get_authorization_code(
            code=request.post.code,
            client_id=client.client_id,
            client_secret=client.client_secret,
        )

        if not authorization_code:
            raise InvalidAuthorizationCodeException()

        if authorization_code.is_expired():
            raise AuthorizationCodeExpiredException()

        await request_validator.delete_authorization_code(
            code=request.post.code,
            client_id=client.client_id,
            client_secret=client.client_secret,
        )

        return client


class PasswordGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_PASSWORD

    async def validate_request(
        self, request: Request, request_validator: BaseRequestValidator
    ) -> ClientModel:
        client = await super().validate_request(request, request_validator)

        if not request.post.password:
            raise MissingPasswordException()

        if not request.post.username:
            raise MissingUsernameException()

        user = await request_validator.get_user(
            username=request.post.username, password=request.post.password
        )

        if not user:
            raise InvalidUsernameOrPasswordException()

        return client


class RefreshTokenGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_REFRESH_TOKEN

    async def validate_request(
        self, request: Request, request_validator: BaseRequestValidator
    ) -> ClientModel:
        client = await super().validate_request(request, request_validator)

        if not request.post.refresh_token:
            raise MissingRefreshTokenException()

        token = await request_validator.get_refresh_token(
            refresh_token=request.post.refresh_token, client_id=client.client_id
        )

        if not token:
            raise InvalidRefreshTokenException()

        if token.refresh_token_expired:
            raise RefreshTokenExpiredException()

        await request_validator.revoke_token(
            refresh_token=request.post.refresh_token, client_id=client.client_id
        )

        return client


class ClientCredentialsGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_CLIENT_CREDENTIALS
