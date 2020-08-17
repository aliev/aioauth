from async_oauth2_provider.config import oauth2_settings
from async_oauth2_provider.types import ResponseType
import time
from typing import Any, Optional

from authlib.oauth2.rfc6749.util import list_to_scope, scope_to_list
from pydantic import BaseModel


class ClientModel(BaseModel):
    client_id: str
    client_secret: str
    client_metadata: dict

    @property
    def grant_types(self):
        return self.client_metadata.get("grant_types", [])

    @property
    def redirect_uris(self):
        return self.client_metadata.get("redirect_uris", [])

    @property
    def response_types(self):
        return self.client_metadata.get("response_types", [])

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types

    def check_response_type(self, response_type):
        return response_type in self.response_types

    @property
    def scope(self):
        return self.client_metadata.get("scope", "")

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    class Config:
        orm_mode = True


class AuthorizationCodeModel(BaseModel):
    code: str
    client_id: str
    redirect_uri: str
    response_type: ResponseType
    scope: str
    nonce: Optional[str]
    auth_time: int
    code_challenge: str
    code_challenge_method: str

    def is_expired(self):
        return (
            self.auth_time + oauth2_settings.AUTHORIZATION_CODE_EXPIRES_IN < time.time()
        )

    class Config:
        orm_mode = True


class TokenModel(BaseModel):
    client_id: str
    token_type: Optional[str] = "Bearer"
    access_token: str
    refresh_token: str
    scope: str
    revoked: bool
    issued_at: int
    expires_in: int

    @property
    def refresh_token_expires_in(self):
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at

    @property
    def refresh_token_expired(self):
        return self.refresh_token_expires_in < time.time()

    class Config:
        orm_mode = True


class UserModel(BaseModel):
    user_id: Any

    class Config:
        orm_model = True
