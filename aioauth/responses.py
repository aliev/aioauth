from http import HTTPStatus
from types import SimpleNamespace
from typing import Optional, Union

from .constances import default_headers
from .structures import CaseInsensitiveDict
from .types import ErrorType


class ErrorResponse(SimpleNamespace):
    """Response for error.

    Used by response_types.
    Used by grant_types.
    """

    error: ErrorType
    description: str
    error_uri: str = ""


class AuthorizationCodeResponse(SimpleNamespace):
    """Response for authorization_code.

    Used by response_types:
        - ResponseTypeAuthorizationCode
    """

    code: str
    scope: str


class TokenResponse(SimpleNamespace):
    """Response for token.

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


class TokenActiveIntrospectionResponse(SimpleNamespace):
    """Response for a valid access token.

    Used by token introspection server.
    """

    scope: str
    client_id: str
    exp: int
    active: bool = True


class TokenInactiveIntrospectionResponse(SimpleNamespace):
    """For an invalid, revoked or expired token.

    Used by token introspection server.
    """

    active: bool = False


class Response(SimpleNamespace):
    """General response class.

    Used by:
        - AuthorizationServer
    """

    content: Optional[
        Union[
            ErrorResponse,
            TokenResponse,
            AuthorizationCodeResponse,
            TokenActiveIntrospectionResponse,
            TokenInactiveIntrospectionResponse,
        ]
    ] = None
    status_code: HTTPStatus = HTTPStatus.OK
    headers: CaseInsensitiveDict = default_headers
