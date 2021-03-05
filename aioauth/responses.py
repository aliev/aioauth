"""
.. code-block:: python

    from aioauth import responses


Response objects used throughout the project.

----
"""

from http import HTTPStatus
from types import SimpleNamespace
from typing import Optional, Union

from .constances import default_headers
from .structures import CaseInsensitiveDict
from .types import ErrorType


class ErrorResponse(SimpleNamespace):
    """Response for errors."""

    error: ErrorType
    description: str
    error_uri: str = ""


class AuthorizationCodeResponse(SimpleNamespace):
    """Response for ``authorization_code``."""

    code: str
    scope: str


class TokenResponse(SimpleNamespace):
    """Response for token."""

    expires_in: int
    refresh_token_expires_in: int
    access_token: str
    refresh_token: str
    scope: str
    token_type: str = "Bearer"


class TokenActiveIntrospectionResponse(SimpleNamespace):
    """Response for a valid access token."""

    scope: str
    client_id: str
    exp: int
    active: bool = True


class TokenInactiveIntrospectionResponse(SimpleNamespace):
    """For an invalid, revoked or expired token."""

    active: bool = False


class Response(SimpleNamespace):
    """General response class."""

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
