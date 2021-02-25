"""
.. code-block:: python

    from aioauth import grant_type
"""

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
from .utils import decode_auth_headers, list_to_scope, scope_to_list


class GrantTypeBase(BaseRequestValidator):
    """Base grant type that all other grant types inherit from."""

    allowed_methods = [RequestMethod.POST]
    grant_type: Optional[GrantType] = None

    async def validate_request(self, request: Request) -> Client:
        """Validates the client request to ensure it is valid."""

        await super().validate_request(request)

        client_id, client_secret = decode_auth_headers(request)

        client = await self.db.get_client(
            request,
            client_id=client_id,
            client_secret=client_secret,
        )

        if not client:
            raise InvalidRequestError(
                request=request,
                description="Invalid client_id parameter value.",
            )
        elif not request.post.grant_type:
            raise InvalidRequestError(
                request=request,
                description="Request is missing grant type.",
            )
        elif self.grant_type != request.post.grant_type:
            raise UnsupportedGrantTypeError(request=request)
        elif not client.check_grant_type(request.post.grant_type):
            raise UnauthorizedClientError(request=request)
        elif not client.check_scope(request.post.scope):
            raise InvalidScopeError(request=request)

        return client

    async def create_token_response(self, request: Request) -> TokenResponse:
        """Creates token response to reply to client."""

        client = await self.validate_request(request)
        token = await self.db.create_token(
            request,
            client.client_id,
            request.post.scope,
        )

        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )


class AuthorizationCodeGrantType(GrantTypeBase):
    """
    The Authorization Code grant type is used by confidential and public
    clients to exchange an authorization code for an access token. After
    the user returns to the client via the redirect URL, the application
    will get the authorization code from the URL and use it to request
    an access token.

    It is recommended that all clients use `RFC 7636 <https://tools.ietf.org/html/rfc7636>`_
    Proof Key for Code Exchange extension with this flow as well to
    provide better security. Note that ``aioauth`` implements RFC 7636
    out-of-the-box.

    See `RFC 6749 section 1.3.1 <https://tools.ietf.org/html/rfc6749#section-1.3.1>`_.
    """

    grant_type: GrantType = GrantType.TYPE_AUTHORIZATION_CODE

    async def validate_request(self, request: Request) -> Client:
        client = await super().validate_request(request)

        if not request.post.redirect_uri:
            raise InvalidRequestError(
                request=request,
                description="Mismatching redirect URI.",
            )
        elif not client.check_redirect_uri(request.post.redirect_uri):
            raise InvalidRequestError(
                request=request,
                description="Invalid redirect URI.",
            )
        elif not request.post.code:
            raise InvalidRequestError(
                request=request,
                description="Missing code parameter.",
            )

        authorization_code = await self.db.get_authorization_code(
            request,
            client.client_id,
            request.post.code,
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
    """
    The Password grant type is a way to exchange a user's credentials
    for an access token. Because the client application has to collect
    the user's password and send it to the authorization server, it is
    not recommended that this grant be used at all anymore.

    See `RFC 6749 section 1.3.3 <https://tools.ietf.org/html/rfc6749#section-1.3.3>`_.

    The latest `OAuth 2.0 Security Best Current Practice <https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.4>`_
    disallows the password grant entirely.
    """

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
    """
    The Refresh Token grant type is used by clients to exchange a
    refresh token for an access token when the access token has expired.
    This allows clients to continue to have a valid access token without
    further interaction with the user.

    See `RFC 6749 section 1.5 <https://tools.ietf.org/html/rfc6749#section-1.5>`_.
    """

    grant_type: GrantType = GrantType.TYPE_REFRESH_TOKEN

    async def validate_request(self, request: Request) -> Client:
        client = await super().validate_request(request)

        if not request.post.refresh_token:
            raise InvalidRequestError(
                request=request,
                description="Missing refresh token parameter.",
            )

        return client

    async def create_token_response(self, request: Request) -> TokenResponse:
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
            new_scope = list_to_scope(
                list(
                    set(scope_to_list(old_token.scope))
                    & set(scope_to_list(request.post.scope))
                )
            )

        token = await self.db.create_token(
            request,
            client.client_id,
            new_scope,
        )

        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )


class ClientCredentialsGrantType(GrantTypeBase):
    """
    The Client Credentials grant type is used by clients to obtain an
    access token outside of the context of a user. This is typically
    used by clients to access resources about themselves rather than to
    access a user's resources.

    See `RFC 6749 section 4.4 <https://tools.ietf.org/html/rfc6749#section-4.4>`_.
    """

    grant_type: GrantType = GrantType.TYPE_CLIENT_CREDENTIALS
