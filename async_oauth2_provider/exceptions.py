from http import HTTPStatus
from typing import Optional
from async_oauth2_provider.types import ErrorType


class OauthException(Exception):
    error: ErrorType
    error_description: Optional[str] = ""
    status_code: HTTPStatus = HTTPStatus.BAD_REQUEST
    error_uri: str = ""

    def __init__(
        self,
        error: ErrorType,
        error_description: str,
        status_code: HTTPStatus,
        error_uri: str = "",
    ):
        self.error = error
        self.error_description = error_description
        self.status_code = status_code
        self.error_uri = error_uri

        super().__init__(error_description)


class InvalidGrantTypeException(OauthException):
    error_description = "Invalid grant_type"
