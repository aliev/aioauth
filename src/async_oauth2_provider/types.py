from enum import Enum


class ErrorType(str, Enum):
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
    TYPE_AUTHORIZATION_CODE = "authorization_code"
    TYPE_PASSWORD = "password"
    TYPE_CLIENT_CREDENTIALS = "client_credentials"
    TYPE_REFRESH_TOKEN = "refresh_token"


class ResponseType(str, Enum):
    TYPE_TOKEN = "token"
    TYPE_CODE = "code"


class EndpointType(str, Enum):
    GRANT_TYPE = "grant_type"
    RESPONSE_TYPE = "response_type"


class RequestMethod(str, Enum):
    GET = "GET"
    POST = "POST"


class CodeChallengeMethod(str, Enum):
    PLAIN = "plain"
    S256 = "S256"
