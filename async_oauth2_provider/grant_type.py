import binascii
from base64 import b64decode
from typing import Type

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.exceptions import (
    AuthorizationCodeExpiredError,
    InsecureTransportError,
    InvalidAuthorizationCodeError,
    InvalidClientError,
    InvalidCredentialsError,
    InvalidGrantTypeError,
    InvalidRedirectUriError,
    InvalidRefreshTokenError,
    InvalidUsernameOrPasswordError,
    MethodNotAllowedError,
    MissingAuthorizationCodeError,
    MissingGrantTypeError,
    MissingPasswordError,
    MissingRedirectUriError,
    MissingRefreshTokenError,
    MissingUsernameError,
    RefreshTokenExpiredError,
)
from async_oauth2_provider.models import Client, Token
from async_oauth2_provider.requests import Request
from async_oauth2_provider.types import GrantType, RequestMethod
from async_oauth2_provider.utils import (
    get_authorization_scheme_param,
    is_secure_transport,
)


class GrantTypeBase:
    grant_type: GrantType
    allowed_methods = (
        RequestMethod.GET,
        RequestMethod.POST,
    )

    def __init__(
        self, db_class: Type[DBBase] = DBBase,
    ):
        self.db_class = db_class

    async def create_token(self, request: Request) -> Token:
        db = self.get_db(request)
        client = await self.validate_request(request, db)
        scope = client.get_allowed_scope(request.post.scope)
        return await db.create_token(client.client_id, scope)

    def get_db(self, request: Request):
        return self.db_class(request)

    async def validate_request(self, request: Request, db: DBBase) -> Client:
        authorization: str = request.headers.get("Authorization", "")
        scheme, param = get_authorization_scheme_param(authorization)

        if not is_secure_transport(request.url):
            raise InsecureTransportError()

        if request.method not in self.allowed_methods:
            raise MethodNotAllowedError()

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
