"""
Errors used throughout the project.
```python
from aioauth import errors
```
"""

from http import HTTPStatus
from typing import Optional
from urllib.parse import urljoin
from .requests import Request

from .collections import HTTPHeaderDict
from .constances import default_headers
from .types import ErrorType


class OAuth2Error(Exception):
    """Base exception that all other exceptions inherit from."""

    error: ErrorType
    description: str = ""
    status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
    error_uri: str = ""
    headers: HTTPHeaderDict = default_headers
    state: str = ""

    def __init__(
        self,
        request: Request,
        description: Optional[str] = None,
        headers: Optional[HTTPHeaderDict] = None,
        state: Optional[str] = None,
    ):
        self.request = request

        if description is not None:
            self.description = description

        if headers is not None:
            self.headers = headers

        if state is not None:
            self.state = state

        if request.settings.ERROR_URI:
            self.error_uri = urljoin(request.settings.ERROR_URI, self.error)

        super().__init__(f"({self.error}) {self.description}")


class MethodNotAllowedError(OAuth2Error):
    """
    The request is valid, but the method trying to be accessed is not
    available to the resource owner.
    """

    description = "HTTP method is not allowed."
    status_code: HTTPStatus = HTTPStatus.METHOD_NOT_ALLOWED
    error: ErrorType = "method_is_not_allowed"


class InvalidRequestError(OAuth2Error):
    """
    The request is missing a required parameter, includes an invalid
    parameter value, includes a parameter more than once, or is
    otherwise malformed.
    """

    error: ErrorType = "invalid_request"


class InvalidClientError(OAuth2Error):
    """
    Client authentication failed (e.g. unknown client, no client
    authentication included, or unsupported authentication method).
    The authorization server **may** return an `HTTP 401` (Unauthorized) status
    code to indicate which HTTP authentication schemes are supported.
    If the client attempted to authenticate via the ``Authorization`` request
    header field, the authorization server **must** respond with an
    `HTTP 401` (Unauthorized) status code, and include the `WWW-Authenticate`
    response header field matching the authentication scheme used by the
    client.
    """

    error: ErrorType = "invalid_client"
    status_code: HTTPStatus = HTTPStatus.UNAUTHORIZED

    def __init__(
        self,
        request: Request,
        description: Optional[str] = None,
        headers: Optional[HTTPHeaderDict] = None,
        state: Optional[str] = None,
    ):
        super().__init__(
            request, description, headers or HTTPHeaderDict(default_headers), state
        )

        auth_values = [f"error={self.error}"]
        if self.description:
            auth_values.append(f"error_description={self.description}")
        if self.error_uri:
            auth_values.append(f"error_uri={self.error_uri}")
        self.headers["WWW-Authenticate"] = "Basic " + ", ".join(auth_values)


class InsecureTransportError(OAuth2Error):
    """An exception will be thrown if the current request is not secure."""

    description = "OAuth 2 MUST utilize https."
    error: ErrorType = "insecure_transport"


class UnsupportedGrantTypeError(OAuth2Error):
    """
    The authorization grant type is not supported by the authorization
    server.
    """

    error: ErrorType = "unsupported_grant_type"


class UnsupportedResponseTypeError(OAuth2Error):
    """
    The authorization server does not support obtaining an authorization
    code using this method.
    """

    error: ErrorType = "unsupported_response_type"


class InvalidGrantError(OAuth2Error):
    """
    The provided authorization grant (e.g. authorization code, resource
    owner credentials) or refresh token is invalid, expired, revoked, does
    not match the redirection URI used in the authorization request, or was
    issued to another client.

    See [RFC6749 section 5.2](https://tools.ietf.org/html/rfc6749#section-5.2).
    """

    error: ErrorType = "invalid_grant"


class MismatchingStateError(OAuth2Error):
    """Unable to securely verify the integrity of the request and response."""

    description = "CSRF Warning! State not equal in request and response."
    error: ErrorType = "mismatching_state"


class UnauthorizedClientError(OAuth2Error):
    """
    The authenticated client is not authorized to use this authorization
    grant type.
    """

    error: ErrorType = "unauthorized_client"


class InvalidScopeError(OAuth2Error):
    """
    The requested scope is invalid, unknown, or malformed, or
    exceeds the scope granted by the resource owner.

    See [RFC6749 section 5.2](https://tools.ietf.org/html/rfc6749#section-5.2).
    """

    error: ErrorType = "invalid_scope"


class ServerError(OAuth2Error):
    """
    The authorization server encountered an unexpected condition that
    prevented it from fulfilling the request.  (This error code is needed
    because a ``HTTP 500`` (Internal Server Error) status code cannot be returned
    to the client via a HTTP redirect.)
    """

    error: ErrorType = "server_error"
    status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
    description: str = "Internal Server Error"


class TemporarilyUnavailableError(OAuth2Error):
    """
    The authorization server is currently unable to handle the request
    due to a temporary overloading or maintenance of the server.
    (This error code is needed because a ``HTTP 503`` (Service Unavailable)
    status code cannot be returned to the client via a HTTP redirect.)
    """

    error: ErrorType = "temporarily_unavailable"


class InvalidRedirectURIError(OAuth2Error):
    """
    The requested redirect URI is missing or not allowed.
    """

    error: ErrorType = "invalid_request"


class UnsupportedTokenTypeError(OAuth2Error):
    """
    The authorization server does not support the revocation of the presented
    token type. That is, the client tried to revoke an access token on a server
    not supporting this feature.
    """

    error: ErrorType = "unsupported_token_type"


class AccessDeniedError(OAuth2Error):
    """
    The resource owner or authorization server denied the request
    """

    error: ErrorType = "access_denied"
