"""
Response objects used throughout the project.
```python
from aioauth import responses
```
"""

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Dict, Optional

from .collections import HTTPHeaderDict
from .constances import default_headers
from .types import ErrorType, TokenType


@dataclass
class ErrorResponse:
    """Response for errors."""

    error: ErrorType
    description: str
    error_uri: str = ""


@dataclass
class AuthorizationCodeResponse:
    """Response for `authorization_code`.

    Used by `aioauth.response_type.ResponseTypeAuthorizationCode`.
    """

    code: str
    scope: str


@dataclass
class NoneResponse:
    """Response for `aioauth.response_type.ResponseTypeNone`.

    See: [OAuth v2 multiple response types](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none),
    """


@dataclass
class TokenResponse:
    """Response for valid token.

    Used by `aioauth.response_type.ResponseTypeToken`.
    """

    expires_in: int
    access_token: str
    scope: str
    refresh_token_expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"


@dataclass
class IdTokenResponse:
    """Response for OpenID id_token.

    Used by `aioauth.response_type.ResponseResponseTypeIdTokenTypeToken`.
    """

    id_token: str


@dataclass
class TokenActiveIntrospectionResponse:
    """Response for a valid access token.

    Used by `aioauth.server.AuthorizationServer.create_token_introspection_response`.
    """

    scope: str
    client_id: str
    token_type: TokenType
    expires_in: int
    active: bool = True


@dataclass
class TokenInactiveIntrospectionResponse:
    """For an invalid, revoked or expired token.

    Used by `aioauth.server.AuthorizationServer.create_token_introspection_response`.
    """

    active: bool = False


@dataclass
class Response:
    """General response class.

    Used by `aioauth.server.AuthorizationServer`.
    """

    content: Dict = field(default_factory=dict)
    status_code: HTTPStatus = HTTPStatus.OK
    headers: HTTPHeaderDict = field(
        default_factory=lambda: default_headers
    )  # pragma: no cover
