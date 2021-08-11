"""
.. code-block:: python

    from aioauth import errors

Errors used throughout the project.

----
"""

from http import HTTPStatus
from typing import Optional
from urllib.parse import urljoin

from .constances import default_headers
from .requests import Request
from .collections import HTTPHeaderDict
from .types import ErrorType


class OAuth2Error(Exception):
    """Base exception that all other exceptions inherit from."""

    error: ErrorType
    description: str = ""
    status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
    error_uri: str = ""
    headers: HTTPHeaderDict = default_headers

    def __init__(
        self,
        request: Request,
        description: Optional[str] = None,
        headers: Optional[HTTPHeaderDict] = None,
    ):
        self.request = request

        if description is not None:
            self.description = description

        if headers is not None:
            self.headers = headers

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
    error = ErrorType.METHOD_IS_NOT_ALLOWED


class InvalidRequestError(OAuth2Error):
    """
    The request is missing a required parameter, includes an invalid
    parameter value, includes a parameter more than once, or is
    otherwise malformed.
    """

    error = ErrorType.INVALID_REQUEST


class InvalidClientError(OAuth2Error):
    """
    Client authentication failed (e.g. unknown client, no client
    authentication included, or unsupported authentication method).
    The authorization server **may** return an ``HTTP 401`` (Unauthorized) status
    code to indicate which HTTP authentication schemes are supported.
    If the client attempted to authenticate via the ``Authorization`` request
    header field, the authorization server **must** respond with an
    ``HTTP 401`` (Unauthorized) status code, and include the ``WWW-Authenticate``
    response header field matching the authentication scheme used by the
    client.
    """

    error = ErrorType.INVALID_CLIENT
    status_code: HTTPStatus = HTTPStatus.UNAUTHORIZED


class InsecureTransportError(OAuth2Error):
    """An exception will be thrown if the current request is not secure."""

    description = "OAuth 2 MUST utilize https."
    error = ErrorType.INSECURE_TRANSPORT


class UnsupportedGrantTypeError(OAuth2Error):
    """
    The authorization grant type is not supported by the authorization
    server.
    """

    error = ErrorType.UNSUPPORTED_GRANT_TYPE


class UnsupportedResponseTypeError(OAuth2Error):
    """
    The authorization server does not support obtaining an authorization
    code using this method.
    """

    error = ErrorType.UNSUPPORTED_RESPONSE_TYPE


class InvalidGrantError(OAuth2Error):
    """
    The provided authorization grant (e.g. authorization code, resource
    owner credentials) or refresh token is invalid, expired, revoked, does
    not match the redirection URI used in the authorization request, or was
    issued to another client.

    See `RFC6749 section 5.2 <https://tools.ietf.org/html/rfc6749#section-5.2>`_.
    """

    error = ErrorType.INVALID_GRANT


class MismatchingStateError(OAuth2Error):
    """Unable to securely verify the integrity of the request and response."""

    description = "CSRF Warning! State not equal in request and response."
    error = ErrorType.MISMATCHING_STATE


class UnauthorizedClientError(OAuth2Error):
    """
    The authenticated client is not authorized to use this authorization
    grant type.
    """

    error = ErrorType.UNAUTHORIZED_CLIENT


class InvalidScopeError(OAuth2Error):
    """
    The requested scope is invalid, unknown, or malformed, or
    exceeds the scope granted by the resource owner.

    See `RFC6749 section 5.2 <https://tools.ietf.org/html/rfc6749#section-5.2>`_.
    """

    error = ErrorType.INVALID_SCOPE


class ServerError(OAuth2Error):
    """
    The authorization server encountered an unexpected condition that
    prevented it from fulfilling the request.  (This error code is needed
    because a ``HTTP 500`` (Internal Server Error) status code cannot be returned
    to the client via a HTTP redirect.)
    """

    error = ErrorType.SERVER_ERROR


class TemporarilyUnavailableError(OAuth2Error):
    """
    The authorization server is currently unable to handle the request
    due to a temporary overloading or maintenance of the server.
    (This error code is needed because a ``HTTP 503`` (Service Unavailable)
    status code cannot be returned to the client via a HTTP redirect.)
    """

    error = ErrorType.TEMPORARILY_UNAVAILABLE
