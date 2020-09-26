from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Optional, Union

from .constances import _default_headers
from .structures import CaseInsensitiveDict
from .types import ErrorType


@dataclass
class ErrorResponse:
    error: ErrorType
    error_description: str
    error_uri: str = ""


@dataclass
class AuthorizationCodeResponse:
    code: str
    scope: str


@dataclass
class TokenResponse:
    expires_in: int
    refresh_token_expires_in: int
    access_token: str
    refresh_token: str
    scope: str
    token_type: str = "Bearer"


@dataclass
class TokenActiveIntrospectionResponse:
    scope: str
    client_id: str
    # TODO: Implement
    # username: str
    exp: int
    active: bool = True


@dataclass
class TokenInactiveIntrospectionResponse:
    active: bool = False


@dataclass
class Response:
    content: Optional[
        Union[
            ErrorResponse,
            TokenResponse,
            AuthorizationCodeResponse,
            TokenActiveIntrospectionResponse,
            TokenInactiveIntrospectionResponse,
        ]
    ]
    status_code: HTTPStatus = HTTPStatus.OK
    headers: CaseInsensitiveDict = field(default_factory=_default_headers)
