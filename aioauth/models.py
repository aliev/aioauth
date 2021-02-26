"""
.. code-block:: python

    from aioauth import models

Memory objects used throughout the project.

----
"""

import time
from types import SimpleNamespace
from typing import List, Optional

from .requests import Request
from .types import CodeChallengeMethod, GrantType, ResponseType
from .utils import create_s256_code_challenge, list_to_scope, scope_to_list


class Client(SimpleNamespace):
    """OAuth2.0 client model object."""

    client_id: str
    """
    Public identifier for the client. It must also be unique across all
    clients that the authorization server handles.
    """

    client_secret: str
    """
    Client secret is a secret known only to the client and the
    authorization server. Used for secure communication between the
    client and authorization server.
    """

    grant_types: List[GrantType] = []
    """
    The method(s) in which an application gets an access token from the
    provider. Each grant type is optimized for a particular use case,
    whether that’s a web app, a native app, a device without the ability
    to launch a web browser, or server-to-server applications.
    """

    redirect_uris: List[str] = []
    """
    After a user successfully authorizes an application, the
    authorization server will redirect the user back to the application
    with either an authorization code or access token in the URL.
    Because the redirect URL will contain sensitive information, it is
    critical that the service doesn’t redirect the user to arbitrary
    locations.
    """

    scope: str = ""
    """
    Scope is a mechanism that limit an application's access to a user's
    account. An application can request one or more scopes, this
    information is then presented to the user in the consent screen, and
    the access token issued to the application will be limited to the
    scopes granted.
    """

    response_types: List[ResponseType] = []
    """A list containing the types of the response expected."""

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        """
        Verifies passed ``redirect_uri`` is part of the Clients's
        ``redirect_uris`` list.
        """
        return redirect_uri in self.redirect_uris

    def check_grant_type(self, grant_type: GrantType) -> bool:
        """
        Verifies passed ``grant_type`` is part of the client's
        ``grant_types`` list.
        """
        return grant_type in self.grant_types

    def check_response_type(self, response_type: ResponseType) -> bool:
        """
        Verifies passed ``response_type`` is part of the client's
        ``response_types`` list.
        """
        return response_type in self.response_types

    def get_allowed_scope(self, scope: str) -> str:
        """
        Returns the allowed ``scope`` given the passed ``scope``.

        Note:
            Note that the passed ``scope`` may contain multiple scopes
            seperated by a space character.
        """
        if not scope:
            return ""
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_scope(self, scope: str) -> bool:
        """Checks if passed ``scope`` is allowed for the client."""
        allowed_scope = self.get_allowed_scope(scope)
        return not (set(scope_to_list(scope)) - set(scope_to_list(allowed_scope)))


class AuthorizationCode(SimpleNamespace):
    code: str
    """
    Authorization code that the client previously received from the
    authorization server.
    """

    client_id: str
    """
    Public identifier for the client. It must also be unique across all
    clients that the authorization server handles.
    """

    redirect_uri: str
    """
    After a user successfully authorizes an application, the
    authorization server will redirect the user back to the application
    with either an authorization code or access token in the URL.
    Because the redirect URL will contain sensitive information, it is
    critical that the service doesn’t redirect the user to arbitrary
    locations.
    """

    response_type: ResponseType
    """A string containing the type of the response expected."""

    scope: str
    """
    Scope is a mechanism that limit an application's access to a user's
    account. An application can request one or more scopes, this
    information is then presented to the user in the consent screen, and
    the access token issued to the application will be limited to the
    scopes granted.
    """

    auth_time: int
    """
    JSON Web Token Claim indicating the time when the authentication
    occurred.
    """

    code_challenge: Optional[str] = None
    """
    Only used when `RFC 7636 <tools.ietf.org/html/rfc7636>`_,
    Proof Key for Code Exchange, is used.

    PKCE works by having the app generate a random value at the
    beginning of the flow called a Code Verifier. The app hashes the
    Code Verifier and the result is called the Code Challenge. The app
    then kicks off the flow in the normal way, except that it includes
    the Code Challenge in the query string for the request to the
    Authorization Server.
    """

    code_challenge_method: Optional[CodeChallengeMethod] = None
    """
    Only used when `RFC 7636 <tools.ietf.org/html/rfc7636>`_,
    Proof Key for Code Exchange, is used.

    Method used to transform the code verifier into the code challenge.
    """

    nonce: Optional[str] = None
    """
    Only used when `RFC 7636 <tools.ietf.org/html/rfc7636>`_,
    Proof Key for Code Exchange, is used.

    Random piece of data.
    """

    def check_code_challenge(self, code_verifier: str) -> bool:
        """Verifies the code challenge."""
        is_valid_code_challenge = False

        if self.code_challenge_method == CodeChallengeMethod.PLAIN:
            # If the "code_challenge_method" was "plain", they are compared directly
            is_valid_code_challenge = code_verifier == self.code_challenge

        if self.code_challenge_method == CodeChallengeMethod.S256:
            # base64url(sha256(ascii(code_verifier))) == code_challenge
            is_valid_code_challenge = (
                create_s256_code_challenge(code_verifier) == self.code_challenge
            )

        return is_valid_code_challenge

    def is_expired(self, request: Request) -> bool:
        """Checks if the authorization time has expired."""
        return (
            self.auth_time + request.settings.AUTHORIZATION_CODE_EXPIRES_IN
            < time.time()
        )


class Token(SimpleNamespace):
    access_token: str
    """
    Token that clients use to make API requests on behalf of the
    resource owner.
    """

    refresh_token: str
    """
    Token used by clients to exchange a refresh token for an access
    token when the access token has expired.
    """

    scope: str
    """
    Scope is a mechanism that limit an application's access to a user's
    account. An application can request one or more scopes, this
    information is then presented to the user in the consent screen, and
    the access token issued to the application will be limited to the
    scopes granted.
    """

    issued_at: int
    """
    Time date in which token was issued at.
    """

    expires_in: int
    """
    Time delta in which token will expire. :py:func:`token_expires_in`
    will give the date time for which the token is to expire.
    """

    client_id: str
    """
    Public identifier for the client. It must also be unique across all
    clients that the authorization server handles.
    """

    token_type: str = "Bearer"
    """
    Type of token expected.
    """

    revoked: bool = False
    """
    Flag that indicates whether or not the token has been revoked.
    """

    def is_expired(self, request: Request) -> bool:
        """Checks if the token has expired."""
        return self.token_expires_in < time.time()

    @property
    def refresh_token_expires_in(self) -> int:
        """Refreshes the 'expires_in' parameter."""
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at

    @property
    def token_expires_in(self) -> int:
        """Time date in which the token will expire in."""
        expires_at = self.issued_at + self.expires_in
        return expires_at

    @property
    def refresh_token_expired(self) -> bool:
        """Checks if refresh token has expired."""
        return self.refresh_token_expires_in < time.time()
