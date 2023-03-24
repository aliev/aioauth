"""
.. code-block:: python

    from aioauth import grant_type

Different OAuth 2.0 grant types.

----
"""
from typing import Generic, Optional
from .errors import (
    InvalidClientError,
    InvalidGrantError,
    InvalidRedirectURIError,
    InvalidRequestError,
    InvalidScopeError,
    MismatchingStateError,
    UnauthorizedClientError,
)
from .models import Client
from .requests import TRequest
from .responses import TokenResponse
from .storage import TStorage
from .utils import enforce_list, enforce_str, generate_token


class GrantTypeBase(Generic[TRequest, TStorage]):
    """Base grant type that all other grant types inherit from."""

    def __init__(self, storage: TStorage, client_id: str, client_secret: Optional[str]):
        self.storage = storage
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope: Optional[str] = None

    async def create_token_response(
        self, request: TRequest, client: Client
    ) -> TokenResponse:
        """Creates token response to reply to client."""
        if self.scope is None:
            raise RuntimeError("validate_request() must be called first")

        token = await self.storage.create_token(
            request,
            client.client_id,
            self.scope,
            generate_token(42),
            generate_token(48),
        )

        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )

    async def validate_request(self, request: TRequest) -> Client:
        """Validates the client request to ensure it is valid."""
        client = await self.storage.get_client(
            request, client_id=self.client_id, client_secret=self.client_secret
        )

        if not client:
            raise InvalidClientError[TRequest](
                request=request, description="Invalid client_id parameter value."
            )

        if not client.check_grant_type(request.post.grant_type):
            raise UnauthorizedClientError[TRequest](request=request)

        if not client.check_scope(request.post.scope):
            raise InvalidScopeError[TRequest](request=request)

        self.scope = request.post.scope
        return client


class AuthorizationCodeGrantType(GrantTypeBase[TRequest, TStorage]):
    """
    The Authorization Code grant type is used by confidential and public
    clients to exchange an authorization code for an access token. After
    the user returns to the client via the redirect URL, the application
    will get the authorization code from the URL and use it to request
    an access token.
    It is recommended that all clients use `RFC 7636 <https://tools.ietf.org/html/rfc7636>`_
    Proof Key for Code Exchange extension with this flow as well to
    provide better security.

    Note:
        Note that ``aioauth`` implements RFC 7636 out-of-the-box.
        See `RFC 6749 section 1.3.1 <https://tools.ietf.org/html/rfc6749#section-1.3.1>`_.
    """

    async def validate_request(self, request: TRequest) -> Client:
        client = await super().validate_request(request)

        if not request.post.redirect_uri:
            raise InvalidRedirectURIError[TRequest](
                request=request, description="Mismatching redirect URI."
            )

        if not client.check_redirect_uri(request.post.redirect_uri):
            raise InvalidRedirectURIError[TRequest](
                request=request, description="Invalid redirect URI."
            )

        if not request.post.code:
            raise InvalidRequestError[TRequest](
                request=request, description="Missing code parameter."
            )

        authorization_code = await self.storage.get_authorization_code(
            request, client.client_id, request.post.code
        )

        if not authorization_code:
            raise InvalidGrantError[TRequest](request=request)

        if (
            authorization_code.code_challenge
            and authorization_code.code_challenge_method
        ):
            if not request.post.code_verifier:
                raise InvalidRequestError[TRequest](
                    request=request, description="Code verifier required."
                )

            is_valid_code_challenge = authorization_code.check_code_challenge(
                request.post.code_verifier
            )
            if not is_valid_code_challenge:
                raise MismatchingStateError[TRequest](request=request)

        if authorization_code.is_expired:
            raise InvalidGrantError[TRequest](request=request)

        self.scope = authorization_code.scope
        return client

    async def create_token_response(
        self, request: TRequest, client: Client
    ) -> TokenResponse:
        token_response = await super().create_token_response(request, client)

        await self.storage.delete_authorization_code(
            request,
            client.client_id,
            request.post.code,
        )

        return token_response


class PasswordGrantType(GrantTypeBase[TRequest, TStorage]):
    """
    The Password grant type is a way to exchange a user's credentials
    for an access token. Because the client application has to collect
    the user's password and send it to the authorization server, it is
    not recommended that this grant be used at all anymore.
    See `RFC 6749 section 1.3.3 <https://tools.ietf.org/html/rfc6749#section-1.3.3>`_.
    The latest `OAuth 2.0 Security Best Current Practice <https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.4>`_
    disallows the password grant entirely.
    """

    async def validate_request(self, request: TRequest) -> Client:
        client = await super().validate_request(request)

        if not request.post.username or not request.post.password:
            raise InvalidRequestError[TRequest](
                request=request, description="Invalid credentials given."
            )

        user = await self.storage.authenticate(request)

        if not user:
            raise InvalidRequestError[TRequest](
                request=request, description="Invalid credentials given."
            )

        return client


class RefreshTokenGrantType(GrantTypeBase[TRequest, TStorage]):
    """
    The Refresh Token grant type is used by clients to exchange a
    refresh token for an access token when the access token has expired.
    This allows clients to continue to have a valid access token without
    further interaction with the user.
    See `RFC 6749 section 1.5 <https://tools.ietf.org/html/rfc6749#section-1.5>`_.
    """

    async def create_token_response(
        self, request: TRequest, client: Client
    ) -> TokenResponse:
        """Validate token request and create token response."""
        old_token = await self.storage.get_token(
            request=request,
            client_id=client.client_id,
            refresh_token=request.post.refresh_token,
        )

        if not old_token or old_token.revoked or old_token.refresh_token_expired:
            raise InvalidGrantError[TRequest](request=request)

        # Revoke old token
        await self.storage.revoke_token(
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

        token = await self.storage.create_token(
            request, client.client_id, new_scope, generate_token(42), generate_token(48)
        )

        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )

    async def validate_request(self, request: TRequest) -> Client:
        client = await super().validate_request(request)

        if not request.post.refresh_token:
            raise InvalidRequestError[TRequest](
                request=request, description="Missing refresh token parameter."
            )

        return client


class ClientCredentialsGrantType(GrantTypeBase[TRequest, TStorage]):
    """
    The Client Credentials grant type is used by clients to obtain an
    access token outside of the context of a user. This is typically
    used by clients to access resources about themselves rather than to
    access a user's resources.
    See `RFC 6749 section 4.4 <https://tools.ietf.org/html/rfc6749#section-4.4>`_.
    """

    async def validate_request(self, request: TRequest) -> Client:
        # client_credentials grant requires a client_secret
        if self.client_secret is None:
            raise InvalidClientError[TRequest](request)

        return await super().validate_request(request)
