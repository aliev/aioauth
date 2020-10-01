"""
async_oauth2_provider.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains the set of OAuth2 exceptions.
"""

from http import HTTPStatus

from .structures import CaseInsensitiveDict
from .requests import Request

from .constances import default_headers
from .types import ErrorType


class OAuth2Exception(Exception):
    error: ErrorType = ErrorType.INVALID_CLIENT
    error_description: str = ""
    status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
    error_uri: str = ""
    headers: CaseInsensitiveDict = default_headers

    def __init__(
        self,
        request: Request,
        error: ErrorType = None,
        error_description: str = None,
        status_code: HTTPStatus = None,
        error_uri: str = None,
        headers: CaseInsensitiveDict = None,
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


class MissingResponseTypeError(OAuth2Exception):
    error_description = "Missing response_type"


class InvalidResponseTypeError(OAuth2Exception):
    error_description = "Invalid response_type"


class MissingGrantTypeError(OAuth2Exception):
    error_description = "Missing grant_type"


class InvalidGrantTypeError(OAuth2Exception):
    error_description = "Invalid grant_type"


class MissingClientIdError(OAuth2Exception):
    error_description = "Missing client_id"


class MissingRedirectUriError(OAuth2Exception):
    error_description = "Missing redirect_uri"


class InvalidRedirectUriError(OAuth2Exception):
    error_description = "Invalid redirect_uri"


class InvalidClientError(OAuth2Exception):
    error_description = "Invalid client_id"


class MissingAuthorizationCodeError(OAuth2Exception):
    error_description = "Missing code"


class MissingUsernameError(OAuth2Exception):
    error_description = "Missing username"


class MissingPasswordError(OAuth2Exception):
    error_description = "Missing password"


class InvalidUsernameOrPasswordError(OAuth2Exception):
    error_description = "Invalid username or password"


class InvalidUserError(OAuth2Exception):
    error_description = "Invalid user"


class MissingRefreshTokenError(OAuth2Exception):
    error_description = "Missing refresh_token"


class InvalidRefreshTokenError(OAuth2Exception):
    error_description = "Invalid refresh_token"


class RefreshTokenExpiredError(OAuth2Exception):
    error_description = "Expired refresh_token"


class InvalidAuthorizationCodeError(OAuth2Exception):
    error_description = "Invalid authorization code"


class AuthorizationCodeExpiredError(OAuth2Exception):
    error_description = "Authorization code expired"


class InvalidCredentialsError(OAuth2Exception):
    status_code: HTTPStatus = HTTPStatus.UNAUTHORIZED
    headers = {"WWW-Authenticate": "Basic"}
    error_description = "Invalid authentication credentials"


class InsecureTransportError(OAuth2Exception):
    error_description = "OAuth 2 MUST utilize https."
    error = ErrorType.INSECURE_TRANSPORT


class MethodNotAllowedError(OAuth2Exception):
    error_description = "HTTP method is not allowed"
    status_code: HTTPStatus = HTTPStatus.METHOD_NOT_ALLOWED


class InvalidCodeVerifierError(OAuth2Exception):
    error_description = "Invalid code_verifier"


class MissingCodeVerifierError(OAuth2Exception):
    error_description = "Missing code_verifier"


class MissingCodeChallengeError(OAuth2Exception):
    error_description = "Missing code_challenge"


class InvalidCodeChallengeMethodError(OAuth2Exception):
    error_description = "Invalid code_challenge_method"
