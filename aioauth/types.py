"""
.. code-block:: python

    from aioauth import types

Containers that contain constants used throughout the project.

----
"""

import sys
from typing import Any, Literal

if sys.version_info >= (3, 13):
    from typing import TypeVar
else:
    from typing_extensions import TypeVar

if sys.version_info >= (3, 11):
    from typing import TypeAlias
else:
    from typing_extensions import TypeAlias


ErrorType: TypeAlias = Literal[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "invalid_scope",
    "unauthorized_client",
    "unsupported_grant_type",
    "unsupported_response_type",
    "unsupported_token_type",
    "insecure_transport",
    "mismatching_state",
    "method_is_not_allowed",
    "server_error",
    "temporarily_unavailable",
    "access_denied",
]


GrantType: TypeAlias = Literal[
    "authorization_code",
    "password",
    "client_credentials",
    "refresh_token",
]


ResponseType: TypeAlias = Literal[
    "token",
    "code",
    "none",
    "id_token",
]


RequestMethod: TypeAlias = Literal["GET", "POST"]


CodeChallengeMethod: TypeAlias = Literal[
    "plain",
    "S256",
]


ResponseMode: TypeAlias = Literal[
    "query",
    "form_post",
    "fragment",
]


TokenType: TypeAlias = Literal["access_token", "refresh_token", "Bearer"]

UserType = TypeVar("UserType", default=Any)
