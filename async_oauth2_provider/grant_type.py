import binascii
from base64 import b64decode

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.exceptions import (
    AuthorizationCodeExpiredError,
    InvalidAuthorizationCodeError,
    InvalidClientError,
    InvalidCredentialsError,
    InvalidGrantTypeError,
    InvalidRedirectUriError,
    InvalidRefreshTokenError,
    InvalidUsernameOrPasswordError,
    MissingAuthorizationCodeError,
    MissingGrantTypeError,
    MissingPasswordError,
    MissingRedirectUriError,
    MissingRefreshTokenError,
    MissingUsernameError,
    RefreshTokenExpiredError,
)
from async_oauth2_provider.models import Client
from async_oauth2_provider.request_validator import BaseRequestValidator
from async_oauth2_provider.requests import Request
from async_oauth2_provider.types import GrantType
from async_oauth2_provider.utils import get_authorization_scheme_param
from responses import TokenResponse


class GrantTypeBase(BaseRequestValidator):
    grant_type: GrantType

    async def create_token_response(self, request: Request) -> TokenResponse:
        db = self.get_db(request)
        client = await self.validate_request(request, db)
        scope = client.get_allowed_scope(request.post.scope)
        token = await db.create_token(client.client_id, scope)
        return TokenResponse.from_orm(token)

    async def validate_request(self, request: Request, db: DBBase) -> Client:
        await super().validate_request(request)

        authorization: str = request.headers.get("Authorization", "")
        scheme, param = get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "basic":
            raise InvalidCredentialsError()

        try:
            data = b64decode(param).decode("ascii")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            raise InvalidCredentialsError()

        client_id, separator, client_secret = data.partition(":")

        if not separator:
            raise InvalidCredentialsError()

        if not request.post.grant_type:
            raise MissingGrantTypeError()

        if self.grant_type != request.post.grant_type:
            raise InvalidGrantTypeError()

        client = await db.get_client(client_id=client_id, client_secret=client_secret)

        if not client:
            raise InvalidClientError()

        if not client.check_grant_type(request.post.grant_type):
            raise InvalidGrantTypeError()

        return client


class AuthorizationCodeGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_AUTHORIZATION_CODE

    async def validate_request(self, request: Request, db: DBBase) -> Client:
        client = await super().validate_request(request, db)

        if not request.post.redirect_uri:
            raise MissingRedirectUriError()

        if not client.check_redirect_uri(request.post.redirect_uri):
            raise InvalidRedirectUriError()

        if not request.post.code:
            raise MissingAuthorizationCodeError()

        authorization_code = await db.get_authorization_code(
            code=request.post.code, client_id=client.client_id,
        )

        if not authorization_code:
            raise InvalidAuthorizationCodeError()

        if authorization_code.is_expired():
            raise AuthorizationCodeExpiredError()

        await db.delete_authorization_code(
            code=request.post.code, client_id=client.client_id,
        )

        return client


class PasswordGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_PASSWORD

    async def validate_request(self, request: Request, db: DBBase) -> Client:
        client = await super().validate_request(request, db)

        if not request.post.password:
            raise MissingPasswordError()

        if not request.post.username:
            raise MissingUsernameError()

        user = await db.get_user(
            username=request.post.username, password=request.post.password
        )

        if not user:
            raise InvalidUsernameOrPasswordError()

        return client


class RefreshTokenGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_REFRESH_TOKEN

    async def validate_request(self, request: Request, db: DBBase) -> Client:
        client = await super().validate_request(request, db)

        if not request.post.refresh_token:
            raise MissingRefreshTokenError()

        token = await db.get_refresh_token(
            refresh_token=request.post.refresh_token, client_id=client.client_id
        )

        if not token:
            raise InvalidRefreshTokenError()

        if token.refresh_token_expired:
            raise RefreshTokenExpiredError()

        await db.revoke_token(
            refresh_token=request.post.refresh_token, client_id=client.client_id
        )

        return client


class ClientCredentialsGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_CLIENT_CREDENTIALS
