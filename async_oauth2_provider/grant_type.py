from http import HTTPStatus

from async_oauth2_provider.types import ErrorType, GrantType
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
    request_validator: BaseRequestValidator

    def __init__(self, request_validator=None):
        self.request_validator = request_validator or BaseRequestValidator()

    async def validate_request(self, request: Request):
        if not request.grant_type:
            raise Exception("Missing grant_type")

        if self.grant_type != request.grant_type:
            raise Exception("Invalid grant_type")

        if not request.client_id:
            raise Exception("Missing client_id")

        if not request.client_secret:
            raise Exception("Missing client_secret")

        client = await self.request_validator.get_client(
            client_id=request.client_id,
            client_secret=request.client_secret,
            request=request,
        )

        if not client:
            raise Exception("Invalid client_id or client_secret")

        if not client.check_grant_type(request.grant_type.value):
            raise Exception("Invalid grant_type")

    async def create_token_response(self, request):
        try:
            self.validate_request(request)
        except Exception as exc:

            return Response(
                status_code=HTTPStatus.BAD_REQUEST,
                body=ErrorResponse(
                    error=ErrorType.INVALID_CLIENT,
                    error_description="This is an error",
                ),
            )

        token = await self.request_validator.create_token(request)

        return Response(status_code=HTTPStatus.OK, body=TokenResponse.from_orm(token))


class AuthorizationCodeGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_AUTHORIZATION_CODE
    request_validator: AuthorizationCodeRequestValidator = AuthorizationCodeRequestValidator()

    async def validate_request(self, request: Request):
        super().validate_request(request)

        if not request.code:
            raise Exception("Missing code")

        authorization_code = await self.request_validator.get_authorization_code(
            request=request, code=request.code,
        )

        if not authorization_code:
            raise Exception("Invalid code")

        if authorization_code.is_expired():
            raise Exception("Authorization code is expired")

        await self.request_validator.delete_authorization_code(
            request=request, code=request.code,
        )


class PasswordGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_PASSWORD
    request_validator: PasswordRequestValidator = PasswordRequestValidator()

    async def validate_request(self, request: Request):
        super().validate_request(request)

        if not request.password or not request.username:
            raise Exception("Invalid username or password")

        user = await self.request_validator.get_user(
            request, request.username, request.password,
        )

        if not user:
            raise Exception("Invalid username or password")


class RefreshTokenGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_REFRESH_TOKEN
    request_validator: RefreshTokenRequestValidator = RefreshTokenRequestValidator()

    async def validate_request(self, request: Request):
        super().validate_request(request)

        if not request.refresh_token:
            raise Exception("Missing refresh_token")

        token = await self.request_validator.get_refresh_token(
            request, request.refresh_token
        )

        if not token:
            raise Exception("Invalid refresh token")

        if token.refresh_token_expired:
            raise Exception("Refresh token expired")

        await self.request_validator.revoke_token(request, request.refresh_token)


class TokenServer:
    pass
