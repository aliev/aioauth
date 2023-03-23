"""
.. code-block:: python

    from aioauth import types

Containers that contain constants used throughout the project.

----
"""
import sys

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


ErrorType = Literal[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "invalid_scope",
    "unauthorized_client",
    "unsupported_grant_type",
    "unsupported_response_type",
    "insecure_transport",
    "mismatching_state",
    "method_is_not_allowed",
    "server_error",
    "temporarily_unavailable",
]


GrantType = Literal[
    "authorization_code",
    "password",
    "client_credentials",
    "refresh_token",
]


ResponseType = Literal[
    "token",
    "code",
    "none",
    "id_token",
]


RequestMethod = Literal["GET", "POST"]


CodeChallengeMethod = Literal[
    "plain",
    "S256",
]


ResponseMode = Literal[
    "query",
    "form_post",
    "fragment",
]


TokenType = Literal["access_token", "refresh_token"]
