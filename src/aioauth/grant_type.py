from typing import Optional

from .base.request_validator import BaseRequestValidator
from .errors import (
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    MismatchingStateError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)
from .models import Client
from .requests import Request
from .responses import TokenResponse
from .types import GrantType, RequestMethod
from .utils import decode_auth_headers


class GrantTypeBase(BaseRequestValidator):
    allowed_methods = [
        RequestMethod.POST,
    ]
    grant_type: Optional[GrantType] = None

    async def create_token_response(self, request: Request) -> TokenResponse:
        client = await self.validate_request(request)
        token = await self.db.create_token(
            request, client.client_id, request.post.scope
        )

        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )

    async def validate_request(self, request: Request) -> Client:
        await super().validate_request(request)

        client_id, client_secret = decode_auth_headers(request)

        client = await self.db.get_client(
            request, client_id=client_id, client_secret=client_secret
        )

        if not client:
            raise InvalidRequestError(
                request=request, description="Invalid client_id parameter value."
            )

        if not request.post.grant_type:
            raise InvalidRequestError(
                request=request, description="Request is missing grant type."
            )

        if self.grant_type != request.post.grant_type:
            raise UnsupportedGrantTypeError(request=request)

        if not client.check_grant_type(request.post.grant_type):
            raise UnauthorizedClientError(request=request)

        if not client.check_scope(request.post.scope):
            raise InvalidScopeError(request=request)

        return client


class AuthorizationCodeGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_AUTHORIZATION_CODE

    async def validate_request(self, request: Request) -> Client:
        client = await super().validate_request(request)

        if not request.post.redirect_uri:
            raise InvalidRequestError(
                request=request, description="Mismatching redirect URI."
            )

        if not client.check_redirect_uri(request.post.redirect_uri):
            raise InvalidRequestError(
                request=request, description="Invalid redirect URI."
            )

        if not request.post.code:
            raise InvalidRequestError(
                request=request, description="Missing code parameter."
            )

        authorization_code = await self.db.get_authorization_code(
            request, client.client_id, request.post.code
        )

        if not authorization_code:
            raise InvalidGrantError(request=request)

        if (
            authorization_code.code_challenge
            and authorization_code.code_challenge_method
        ):
            if not request.post.code_verifier:
                raise InvalidRequestError(
                    request=request, description="Code verifier required."
                )

            is_valid_code_challenge = authorization_code.check_code_challenge(
                request.post.code_verifier
            )
            if not is_valid_code_challenge:
                raise MismatchingStateError(request=request)

        if authorization_code.is_expired(request):
            raise InvalidGrantError(request=request)

        await self.db.delete_authorization_code(
            request, client.client_id, request.post.code
        )

        return client


class PasswordGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_PASSWORD

    async def validate_request(self, request: Request) -> Client:
        client = await super().validate_request(request)

        if not request.post.password or not request.post.password:
            raise InvalidGrantError(
                request=request, description="Invalid credentials given."
            )

        user = await self.db.authenticate(request)

        if not user:
            raise InvalidGrantError(
                request=request, description="Invalid credentials given."
            )

        return client


class RefreshTokenGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_REFRESH_TOKEN

    async def validate_request(self, request: Request) -> Client:
        client = await super().validate_request(request)

        if not request.post.refresh_token:
            raise InvalidRequestError(
                request=request, description="Missing refresh token parameter."
            )

        token = await self.db.get_token(
            request=request,
            client_id=client.client_id,
            refresh_token=request.post.refresh_token,
        )

        if not token:
            raise InvalidGrantError(request=request)

        if token.refresh_token_expired:
            raise InvalidGrantError(request=request)

        await self.db.revoke_token(request, request.post.refresh_token)

        return client


class ClientCredentialsGrantType(GrantTypeBase):
    grant_type: GrantType = GrantType.TYPE_CLIENT_CREDENTIALS
