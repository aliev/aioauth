import time
from typing import List, Optional, Text

from pydantic import BaseModel
from pydantic.networks import AnyHttpUrl

from .config import settings
from .types import CodeChallengeMethod, GrantType, ResponseType
from .utils import list_to_scope, scope_to_list


class ClientMetadata(BaseModel):
    grant_types: List[GrantType] = []
    response_types: List[ResponseType] = []
    redirect_uris: List[AnyHttpUrl] = []
    scope: Text = ""

    class Config:
        orm_mode = True


class Client(BaseModel):
    client_id: Text
    client_secret: Text
    client_metadata: ClientMetadata

    def check_redirect_uri(self, redirect_uri) -> bool:
        return redirect_uri in self.client_metadata.redirect_uris

    def check_grant_type(self, grant_type: GrantType) -> bool:
        return grant_type in self.client_metadata.grant_types

    def check_response_type(self, response_type: ResponseType) -> bool:
        return response_type in self.client_metadata.response_types

    def get_allowed_scope(self, scope) -> Text:
        if not scope:
            return ""
        allowed = set(self.client_metadata.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    class Config:
        orm_mode = True


class AuthorizationCode(BaseModel):
    state: Text = ""
    code: Text
    client_id: Text
    redirect_uri: Text
    response_type: ResponseType
    scope: Text
    nonce: Optional[Text]
    auth_time: int
    code_challenge: Optional[Text]
    code_challenge_method: CodeChallengeMethod

    def is_expired(self) -> bool:
        return self.auth_time + settings.AUTHORIZATION_CODE_EXPIRES_IN < time.time()

    class Config:
        orm_mode = True


class Token(BaseModel):
    client_id: Text
    token_type: Optional[Text] = "Bearer"
    access_token: Text
    refresh_token: Text
    scope: Text
    revoked: bool = False
    issued_at: int
    expires_in: int

    @property
    def refresh_token_expires_in(self) -> int:
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at

    @property
    def refresh_token_expired(self) -> bool:
        return self.refresh_token_expires_in < time.time()

    class Config:
        orm_mode = True
