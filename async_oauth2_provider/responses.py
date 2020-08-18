from async_oauth2_provider.types import ErrorType
from typing import Dict, Optional, Union
from pydantic import BaseModel
from http import HTTPStatus


class ErrorResponse(BaseModel):
    error: ErrorType
    error_description: str
    error_uri: Optional[str]


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
    headers: Dict = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    body: Union[ErrorResponse, TokenResponse]
