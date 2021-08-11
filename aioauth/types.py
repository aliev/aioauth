"""
.. code-block:: python

    from aioauth import types

Containers that contain constants used throughout the project.
----
"""

from enum import Enum


class ErrorType(str, Enum):
    """Error types."""

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    INVALID_SCOPE = "invalid_scope"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INSECURE_TRANSPORT = "insecure_transport"
    MISMATCHING_STATE = "mismatching_state"
    METHOD_IS_NOT_ALLOWED = "method_is_not_allowed"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"


class GrantType(str, Enum):
    """Grant types."""

    TYPE_AUTHORIZATION_CODE = "authorization_code"
    TYPE_PASSWORD = "password"
    TYPE_CLIENT_CREDENTIALS = "client_credentials"
    TYPE_REFRESH_TOKEN = "refresh_token"


class ResponseType(str, Enum):
    """Response types."""

    TYPE_TOKEN = "token"
    TYPE_CODE = "code"
    TYPE_NONE = "none"
    TYPE_ID_TOKEN = "id_token"


class RequestMethod(str, Enum):
    """Request types."""

    GET = "GET"
    POST = "POST"


class CodeChallengeMethod(str, Enum):
    """Code challenge types."""

    PLAIN = "plain"
    S256 = "S256"


class ResponseMode(str, Enum):
    """Response modes."""

    MODE_QUERY = "query"
    MODE_FORM_POST = "form_post"
    MODE_FRAGMENT = "fragment"
