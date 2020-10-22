import time
from dataclasses import dataclass, field
from typing import List, Optional, Text

from .config import settings
from .types import CodeChallengeMethod, GrantType, ResponseType
from .utils import create_s256_code_challenge, list_to_scope, scope_to_list


@dataclass
class ClientMetadata:
    grant_types: List[GrantType] = field(default_factory=list)
    response_types: List[ResponseType] = field(default_factory=list)
    redirect_uris: List[str] = field(default_factory=list)
    scope: Text = ""


@dataclass
class Client:
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

    def check_scope(self, scope: str) -> bool:
        allowed_scope = self.get_allowed_scope(scope)
        return not (set(scope_to_list(scope)) - set(scope_to_list(allowed_scope)))


@dataclass
class AuthorizationCode:
    code: Text
    client_id: Text
    redirect_uri: Text
    response_type: ResponseType
    scope: Text
    auth_time: int
    code_challenge: Optional[Text] = None
    code_challenge_method: Optional[CodeChallengeMethod] = None
    nonce: Optional[Text] = None

    def check_code_challenge(self, code_verifier: str) -> bool:
        is_valid_code_challenge = False

        if self.code_challenge_method == CodeChallengeMethod.PLAIN:
            # If the "code_challenge_method" was "plain", they are compared directly
            is_valid_code_challenge = code_verifier == self.code_challenge

        if self.code_challenge_method == CodeChallengeMethod.S256:
            # base64url(sha256(ascii(code_verifier))) == code_challenge
            is_valid_code_challenge = (
                create_s256_code_challenge(code_verifier) == self.code_challenge
            )

        return is_valid_code_challenge

    @property
    def is_expired(self) -> bool:
        return self.auth_time + settings.AUTHORIZATION_CODE_EXPIRES_IN < time.time()


@dataclass
class Token:
    access_token: Text
    refresh_token: Text
    scope: Text
    issued_at: int
    expires_in: int
    client_id: Text
    token_type: Text = "Bearer"
    revoked: bool = False

    @property
    def refresh_token_expires_in(self) -> int:
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at

    @property
    def refresh_token_expired(self) -> bool:
        return self.refresh_token_expires_in < time.time()
