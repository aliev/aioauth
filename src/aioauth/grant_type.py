from typing import Tuple

from .base.database import BaseDB
from .errors import (
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    MismatchingStateError,
    UnauthorizedClientError,
)
from .models import Client
from .requests import Request
from .responses import TokenResponse
from .utils import decode_auth_headers, enforce_list, enforce_str


class GrantTypeBase:
    def __init__(self, db: BaseDB):
        self.db = db

    async def create_token_response(self, request: Request) -> TokenResponse:
        """ Validate token request and create token response. """
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
        client_id, client_secret = self.get_client_credentials(request)

        client = await self.db.get_client(
            request, client_id=client_id, client_secret=client_secret
        )

        if not client:
            raise InvalidRequestError(
                request=request, description="Invalid client_id parameter value."
            )

        if not client.check_grant_type(request.post.grant_type):  # type: ignore
            raise UnauthorizedClientError(request=request)

        if not client.check_scope(request.post.scope):
            raise InvalidScopeError(request=request)

        return client

    def get_client_credentials(self, request: Request) -> Tuple[str, str]:
        client_id = request.post.client_id
        client_secret = request.post.client_secret

        if client_id is None or client_secret is None:
            client_id, client_secret = decode_auth_headers(request)

        return client_id, client_secret


class AuthorizationCodeGrantType(GrantTypeBase):
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

        if authorization_code.is_expired:
            raise InvalidGrantError(request=request)

        await self.db.delete_authorization_code(
            request, client.client_id, request.post.code
        )

        return client


class PasswordGrantType(GrantTypeBase):
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
    async def create_token_response(self, request: Request) -> TokenResponse:
        """ Validate token request and create token response. """
        client = await self.validate_request(request)

        old_token = await self.db.get_token(
            request=request,
            client_id=client.client_id,
            refresh_token=request.post.refresh_token,
        )

        if not old_token or old_token.revoked or old_token.refresh_token_expired:
            raise InvalidGrantError(request=request)

        # Revoke old token
        await self.db.revoke_token(
            request=request, refresh_token=old_token.refresh_token
        )

        # new token should have at max the same scope as the old token
        # (see https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/)
        new_scope = old_token.scope
        if request.post.scope:
            # restrict requested tokens to requested scopes in the old token
            new_scope = enforce_str(
                list(
                    set(enforce_list(old_token.scope))
                    & set(enforce_list(request.post.scope))
                )
            )

        token = await self.db.create_token(request, client.client_id, new_scope)

        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )

    async def validate_request(self, request: Request) -> Client:
        client = await super().validate_request(request)

        if not request.post.refresh_token:
            raise InvalidRequestError(
                request=request, description="Missing refresh token parameter."
            )

        return client


class ClientCredentialsGrantType(GrantTypeBase):
    ...
