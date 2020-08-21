from http import HTTPStatus
from typing import Optional

from async_oauth2_provider.types import ErrorType


class OAuth2Exception(Exception):
    error: ErrorType = ErrorType.INVALID_CLIENT
    error_description: Optional[str] = ""
    status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
    error_uri: str = ""
    headers: dict = {}

    def __init__(
        self,
        error: ErrorType = None,
        error_description: str = None,
        status_code: HTTPStatus = None,
        error_uri: str = None,
        headers: dict = None,
    ):
        if error is not None:
            self.error = error

        if error_description is not None:
            self.error_description = error_description

        if status_code is not None:
            self.status_code = status_code

        if error_uri is not None:
            self.error_uri = error_uri

        if headers is not None:
            self.headers = headers

        super().__init__(self.error_description)


class MissingScopeException(OAuth2Exception):
    error_description = "Missing scope"


class MissingResponseTypeException(OAuth2Exception):
    error_description = "Missing response_type"


class InvalidResponseTypeException(OAuth2Exception):
    error_description = "Invalid response_type"


class MissingGrantTypeException(OAuth2Exception):
    error_description = "Missing grant_type"


class InvalidGrantTypeException(OAuth2Exception):
    error_description = "Invalid grant_type"


class MissingClientIdException(OAuth2Exception):
    error_description = "Missing client_id"


class MissingRedirectUri(OAuth2Exception):
    error_description = "Missing redirect_uri"


class InvalidRedirectUri(OAuth2Exception):
    error_description = "Invalid redirect_uri"


class InvalidClientException(OAuth2Exception):
    error_description = "Invalid client_id"


class MissingAuthorizationCodeException(OAuth2Exception):
    error_description = "Missing code"


class MissingUsernameException(OAuth2Exception):
    error_description = "Missing username"


class MissingPasswordException(OAuth2Exception):
    error_description = "Missing password"


class InvalidUsernameOrPasswordException(OAuth2Exception):
    error_description = "Invalid username or password"


class MissingRefreshTokenException(OAuth2Exception):
    error_description = "Missing refresh_token"


class InvalidRefreshTokenException(OAuth2Exception):
    error_description = "Invalid refresh_token"


class RefreshTokenExpiredException(OAuth2Exception):
    error_description = "Expired refresh_token"


class InvalidAuthorizationCodeException(OAuth2Exception):
    error_description = "Invalid authorization code"


class AuthorizationCodeExpiredException(OAuth2Exception):
    error_description = "Authorization code expired"


class InvalidCredentialsException(OAuth2Exception):
    status_code: HTTPStatus = HTTPStatus.UNAUTHORIZED
    headers = {"WWW-Authenticate": "Basic"}
    error_description = "Invalid authentication credentials"


class InsecureTransportError(OAuth2Exception):
    error_description = "OAuth 2 MUST utilize https."


class HTTPMethodNotAllowed(OAuth2Exception):
    error_description = "HTTP method is not allowed"
    status_code: HTTPStatus = HTTPStatus.METHOD_NOT_ALLOWED
