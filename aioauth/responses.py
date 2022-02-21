"""
.. code-block:: python

    from aioauth import responses

Response objects used throughout the project.

----
"""
import dataclasses
from http import HTTPStatus
from typing import Dict

from .collections import HTTPHeaderDict
from .constances import default_headers
from .types import ErrorType, TokenType


@dataclasses.dataclass
class ErrorResponse:
    """Response for errors."""

    error: ErrorType
    description: str
    error_uri: str = ""


@dataclasses.dataclass
class AuthorizationCodeResponse:
    """Response for ``authorization_code``.

    Used by :py:class:`aioauth.response_type.ResponseTypeAuthorizationCode`.
    """

    code: str
    scope: str


@dataclasses.dataclass
class NoneResponse:
    """Response for :py:class:`aioauth.response_type.ResponseTypeNone`.

    See: `OAuth v2 multiple response types <openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none>`_,
    """


@dataclasses.dataclass
class TokenResponse:
    """Response for valid token.

    Used by :py:class:`aioauth.response_type.ResponseTypeToken`.
    """

    expires_in: int
    refresh_token_expires_in: int
    access_token: str
    refresh_token: str
    scope: str
    token_type: str = "Bearer"


@dataclasses.dataclass
class IdTokenResponse:
    """Response for OpenID id_token.

    Used by :py:class:`aioauth.response_type.ResponseResponseTypeIdTokenTypeToken`.
    """

    id_token: str


@dataclasses.dataclass
class TokenActiveIntrospectionResponse:
    """Response for a valid access token.

    Used by :py:meth:`aioauth.server.AuthorizationServer.create_token_introspection_response`.
    """

    scope: str
    client_id: str
    token_type: TokenType
    expires_in: int
    active: bool = True


@dataclasses.dataclass
class TokenInactiveIntrospectionResponse:
    """For an invalid, revoked or expired token.

    Used by :py:meth:`aioauth.server.AuthorizationServer.create_token_introspection_response`.
    """

    active: bool = False


@dataclasses.dataclass
class Response:
    """General response class.

    Used by :py:class:`aioauth.server.AuthorizationServer`.
    """

    content: Dict = dataclasses.field(default_factory=dict)
    status_code: HTTPStatus = HTTPStatus.OK
    headers: HTTPHeaderDict = default_headers
