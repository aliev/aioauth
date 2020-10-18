"""
async_oauth2_provider.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Error used both by OAuth 2 clients and providers to represent the spec
defined error responses for all four core grant types.
"""

from http import HTTPStatus
from typing import Optional

from .constances import default_headers
from .requests import Request
from .structures import CaseInsensitiveDict
from .types import ErrorType


class OAuth2Exception(Exception):
    request: Optional[Request] = None
    error: ErrorType
    description: str = ""
    status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
    error_uri: str = ""
    headers: CaseInsensitiveDict = default_headers

    def __init__(
        self,
        request: Optional[Request] = None,
        description: Optional[str] = None,
        status_code: Optional[HTTPStatus] = None,
        error_uri: Optional[str] = None,
        headers: Optional[CaseInsensitiveDict] = None,
    ):
        if request is not None:
            self.request = request

        if description is not None:
            self.description = description

        if status_code is not None:
            self.status_code = status_code

        if error_uri is not None:
            self.error_uri = error_uri

        if headers is not None:
            self.headers = headers

        super().__init__(f"({self.error}) {self.description}")


class MethodNotAllowedError(OAuth2Exception):
    description = "HTTP method is not allowed."
    status_code: HTTPStatus = HTTPStatus.METHOD_NOT_ALLOWED
    error = "method_is_not_allowed"


class InvalidRequestError(OAuth2Exception):
    """
    The request is missing a required parameter, includes an invalid
    parameter value, includes a parameter more than once, or is
    otherwise malformed.
    """

    error = ErrorType.INVALID_REQUEST


class InvalidClientError(OAuth2Exception):
    """
    Client authentication failed (e.g. unknown client, no client
    authentication included, or unsupported authentication method).
    The authorization server MAY return an HTTP 401 (Unauthorized) status
    code to indicate which HTTP authentication schemes are supported.
    If the client attempted to authenticate via the "Authorization" request
    header field, the authorization server MUST respond with an
    HTTP 401 (Unauthorized) status code, and include the "WWW-Authenticate"
    response header field matching the authentication scheme used by the
    client.
    """

    error = ErrorType.INVALID_CLIENT
    status_code: HTTPStatus = HTTPStatus.UNAUTHORIZED


class InsecureTransportError(OAuth2Exception):
    description = "OAuth 2 MUST utilize https."
    error = ErrorType.INSECURE_TRANSPORT


class UnsupportedGrantTypeError(OAuth2Exception):
    """
    The authorization grant type is not supported by the authorization
    server.
    """

    error = ErrorType.UNSUPPORTED_GRANT_TYPE


class UnsupportedResponseTypeError(OAuth2Exception):
    """
    The authorization server does not support obtaining an authorization
    code using this method.
    """

    error = ErrorType.UNSUPPORTED_RESPONSE_TYPE


class InvalidGrantError(OAuth2Exception):
    """
    The provided authorization grant (e.g. authorization code, resource
    owner credentials) or refresh token is invalid, expired, revoked, does
    not match the redirection URI used in the authorization request, or was
    issued to another client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """

    error = ErrorType.INVALID_GRANT


class MismatchingStateError(OAuth2Exception):
    description = "CSRF Warning! State not equal in request and response."
    error = ErrorType.MISMATCHING_STATE


# TODO: Integrate
class UnauthorizedClientError(OAuth2Exception):
    """
    The authenticated client is not authorized to use this authorization
    grant type.
    """

    error = ErrorType.UNAUTHORIZED_CLIENT


# TODO: Integrate
class InvalidScopeError(OAuth2Exception):
    """
    The requested scope is invalid, unknown, or malformed, or
    exceeds the scope granted by the resource owner.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """

    error = ErrorType.INVALID_SCOPE
