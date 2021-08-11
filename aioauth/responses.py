"""
.. code-block:: python

    from aioauth import responses

Response objects used throughout the project.
---------------------------------------------
"""

from http import HTTPStatus
from typing import Dict, NamedTuple, Optional

from .constances import default_headers
from .collections import HTTPHeaderDict
from .types import ErrorType


class ErrorResponse(NamedTuple):
    """Response for errors."""

    error: ErrorType
    description: str
    error_uri: str = ""


class AuthorizationCodeResponse(NamedTuple):
    """Response for ``authorization_code``.

    Used by :py:class:`aioauth.response_type.ResponseTypeAuthorizationCode`.
    """

    code: str
    scope: str


class NoneResponse(NamedTuple):
    """Response for :py:class:`aioauth.response_type.ResponseTypeNone`.

    See: `OAuth v2 multiple response types <openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none>`_,
    """


class TokenResponse(NamedTuple):
    """Response for valid token.

    Used by :py:class:`aioauth.response_type.ResponseTypeToken`.
    """

    expires_in: int
    refresh_token_expires_in: int
    access_token: str
    refresh_token: str
    scope: str
    token_type: str = "Bearer"


class IdTokenResponse(NamedTuple):
    """Response for OpenID id_token.

    Used by :py:class:`aioauth.response_type.ResponseResponseTypeIdTokenTypeToken`.
    """

    id_token: str


class TokenActiveIntrospectionResponse(NamedTuple):
    """Response for a valid access token.

    Used by :py:meth:`aioauth.server.AuthorizationServer.create_token_introspection_response`.
    """

    scope: str
    client_id: str
    exp: int
    active: bool = True


class TokenInactiveIntrospectionResponse(NamedTuple):
    """For an invalid, revoked or expired token.

    Used by :py:meth:`aioauth.server.AuthorizationServer.create_token_introspection_response`.
    """

    active: bool = False


class Response(NamedTuple):
    """General response class.

    Used by :py:class:`aioauth.server.AuthorizationServer`.
    """

    content: Optional[Dict] = {}
    status_code: HTTPStatus = HTTPStatus.OK
    headers: HTTPHeaderDict = default_headers
