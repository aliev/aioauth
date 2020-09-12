from http import HTTPStatus
from typing import Dict, Optional, Union

from pydantic import BaseModel

from .constances import default_headers
from .types import ErrorType


class ErrorResponse(BaseModel):
    error: ErrorType
    error_description: str
    error_uri: Optional[str]


class AuthorizationCodeResponse(BaseModel):
    code: str
    scope: str
    state: Optional[str]

    class Config:
        orm_mode = True


class TokenResponse(BaseModel):
    expires_in: int
    refresh_token_expires_in: int
    access_token: str
    refresh_token: str
    token_type: Optional[str] = "Bearer"
    scope: str

    class Config:
        orm_mode = True


class Response(BaseModel):
    status_code: HTTPStatus = HTTPStatus.OK
    headers: Dict[str, str] = default_headers
    content: Optional[
        Union[ErrorResponse, TokenResponse, AuthorizationCodeResponse]
    ] = None
