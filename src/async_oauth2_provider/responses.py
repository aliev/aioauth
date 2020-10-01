from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Optional, Union

from .constances import _default_headers
from .structures import CaseInsensitiveDict
from .types import ErrorType


@dataclass
class ErrorResponse:
    """ Response for error.

    Used by response_types.
    Used by grant_types.
    """

    error: ErrorType
    error_description: str
    error_uri: str = ""


@dataclass
class AuthorizationCodeResponse:
    """ Response for authorization_code.

    Used by response_types:
        - ResponseTypeAuthorizationCode
    """

    code: str
    scope: str


@dataclass
class TokenResponse:
    """ Response for token.

    Used by grant_types.
    Used by response_types:
        - ResponseTypeToken
    """

    expires_in: int
    refresh_token_expires_in: int
    access_token: str
    refresh_token: str
    scope: str
    token_type: str = "Bearer"


@dataclass
class TokenActiveIntrospectionResponse:
    """ Response for a valid access token.

    Used by token introspection endpoint.
    """

    scope: str
    client_id: str
    exp: int
    active: bool = True


@dataclass
class TokenInactiveIntrospectionResponse:
    """ For an invalid, revoked or expired token.

    Used by token introspection endpoint.
    """

    active: bool = False


@dataclass
class Response:
    """ General response class.

    Used by:
        - OAuth2Endpoint
    """

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
