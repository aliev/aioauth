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


class RequestType(Enum):
    METHOD_GET = "GET"
    METHOD_POST = "POST"
