from enum import Enum


class ErrorType(Enum):
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    INVALID_SCOPE = "invalid_scope"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"


class GrantType(Enum):
    TYPE_AUTHORIZATION_CODE = "authorization_code"
    TYPE_PASSWORD = "password"
    TYPE_CLIENT_CREDENTIALS = "client_credentials"
    TYPE_REFRESH_TOKEN = "refresh_token"


class ResponseType(Enum):
    TYPE_TOKEN = "token"
    TYPE_CODE = "code"


class RequestMethod(Enum):
    GET = "GET"
    POST = "POST"


class CodeChallengeMethod(Enum):
    PLAIN = "plain"
    S256 = "S256"
