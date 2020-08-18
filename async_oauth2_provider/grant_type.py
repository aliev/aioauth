import binascii
from base64 import b64decode
from http import HTTPStatus
from typing import Type

from async_oauth2_provider.utils import (
    get_authorization_scheme_param,
    is_secure_transport,
)

from async_oauth2_provider.exceptions import (
    AuthorizationCodeExpiredException,
    InsecureTransportError,
    InvalidAuthorizationCodeException,
    InvalidCredentialsException,
    MissingAuthorizationCodeException,
    InvalidGrantTypeException,
    InvalidRefreshTokenException,
    InvalidUsernameOrPasswordException,
    MissingGrantTypeException,
    InvalidClientException,
    MissingPasswordException,
    MissingRefreshTokenException,
    MissingUsernameException,
    OAuth2Exception,
    RefreshTokenExpiredException,
)

from async_oauth2_provider.types import GrantType
from async_oauth2_provider.requests import Request
from async_oauth2_provider.responses import ErrorResponse, Response, TokenResponse
from async_oauth2_provider.request_validators import (
    BaseRequestValidator,
    AuthorizationCodeRequestValidator,
    PasswordRequestValidator,
    RefreshTokenRequestValidator,
)


class GrantTypeBase:
    grant_type: GrantType
    request_validator_class: Type[BaseRequestValidator] = BaseRequestValidator

    def __init__(
        self, request_validator_class: Type[BaseRequestValidator] = None,
    ):
        if request_validator_class is not None:
            self.request_validator_class = request_validator_class

    async def create_token_response(self, request: Request) -> Response:
        request_validator = self.get_request_validator(request)

        await self.validate_request(request, request_validator)

        token = await request_validator.create_token()

        return Response(status_code=HTTPStatus.OK, body=TokenResponse.from_orm(token))

    def __str__(self) -> str:
        return f"<{self.__class__.__name__} {self.grant_type.value}>"

    def __repr__(self) -> str:
        return self.__str__()

    def get_request_validator(self, request: Request):
        return self.request_validator_class(request)

    async def validate_request(
        self, request: Request, request_validator: BaseRequestValidator
    ):
        authorization: str = request.headers.get("Authorization", "")
        scheme, param = get_authorization_scheme_param(authorization)

        if not is_secure_transport(request.url):
            raise InsecureTransportError()

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


class AuthorizationCodeGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_AUTHORIZATION_CODE
    request_validator_class: Type[AuthorizationCodeRequestValidator]

    async def validate_request(
        self, request: Request, request_validator: AuthorizationCodeRequestValidator
    ):
        await super().validate_request(request, request_validator)

        if not request.post.code:
            raise MissingAuthorizationCodeException()

        authorization_code = await request_validator.get_authorization_code(
            code=request.post.code
        )

        if not authorization_code:
            raise InvalidAuthorizationCodeException()

        if authorization_code.is_expired():
            raise AuthorizationCodeExpiredException()

        await request_validator.delete_authorization_code(code=request.post.code)


class PasswordGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_PASSWORD
    request_validator: Type[PasswordRequestValidator]

    async def validate_request(
        self, request: Request, request_validator: PasswordRequestValidator
    ):
        await super().validate_request(request, request_validator)

        if not request.post.password:
            raise MissingPasswordException()

        if not request.post.username:
            raise MissingUsernameException()

        user = await request_validator.get_user(
            request.post.username, request.post.password
        )

        if not user:
            raise InvalidUsernameOrPasswordException()


class RefreshTokenGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_REFRESH_TOKEN
    request_validator: Type[RefreshTokenRequestValidator]

    async def validate_request(
        self, request: Request, request_validator: RefreshTokenRequestValidator
    ):
        await super().validate_request(request, request_validator)

        if not request.post.refresh_token:
            raise MissingRefreshTokenException()

        token = await request_validator.get_refresh_token(request.post.refresh_token)

        if not token:
            raise InvalidRefreshTokenException()

        if token.refresh_token_expired:
            raise RefreshTokenExpiredException()

        await request_validator.revoke_token(request.post.refresh_token)


class ClientCredentialsGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_CLIENT_CREDENTIALS


class TokenEndpoint:
    grant_type_classes = {
        GrantType.TYPE_AUTHORIZATION_CODE: AuthorizationCodeGrantType,
        GrantType.TYPE_REFRESH_TOKEN: PasswordGrantType,
        GrantType.TYPE_REFRESH_TOKEN: RefreshTokenGrantType,
        GrantType.TYPE_CLIENT_CREDENTIALS: ClientCredentialsGrantType,
    }

    def __init__(self, request_validator_class: Request, grant_types: dict = {}):
        self.request_validator_class = request_validator_class
        self.grant_types = grant_types

    async def create_token_response(self, request) -> Response:
        if not request.post.grant_type:
            raise MissingGrantTypeException()

        if request.post.grant_type not in self.grant_type_classes:
            raise InvalidGrantTypeException()

        GrantTypeClass = self.grant_type_classes[request.post.grant_type]

        grant_type = GrantTypeClass(self.request_validator_class, request)

        return await grant_type.create_token_response()

    async def __call__(self, request: Request) -> Response:
        try:
            return await self.create_token_response(request)
        except OAuth2Exception as exc:
            return Response(
                headers=exc.headers,
                status_code=exc.status_code,
                body=ErrorResponse(
                    error=exc.error, error_description=exc.error_description,
                ),
            )
