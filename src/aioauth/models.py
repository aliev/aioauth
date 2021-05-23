import time
from typing import List, NamedTuple, Optional, Text

from .types import CodeChallengeMethod, GrantType, ResponseType
from .utils import create_s256_code_challenge, enforce_list, enforce_str


class Client(NamedTuple):
    client_id: Text
    client_secret: Text
    grant_types: List[GrantType] = []
    response_types: List[ResponseType] = []
    redirect_uris: List[str] = []
    scope: Text = ""

    def check_redirect_uri(self, redirect_uri) -> bool:
        return redirect_uri in self.redirect_uris

    def check_grant_type(self, grant_type: GrantType) -> bool:
        return grant_type in self.grant_types

    def check_response_type(self, response_type: str) -> bool:
        return not (set(enforce_list(response_type)) - set(self.response_types))

    def get_allowed_scope(self, scope) -> Text:
        if not scope:
            return ""
        allowed = set(self.scope.split())
        scopes = enforce_list(scope)
        return enforce_str([s for s in scopes if s in allowed])

    def check_scope(self, scope: str) -> bool:
        allowed_scope = self.get_allowed_scope(scope)
        return not (set(enforce_list(scope)) - set(enforce_list(allowed_scope)))


class AuthorizationCode(NamedTuple):
    code: Text
    client_id: Text
    redirect_uri: Text
    response_type: str
    scope: Text
    auth_time: int
    expires_in: int
    code_challenge: Optional[Text] = None
    code_challenge_method: Optional[Text] = None
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
        return self.auth_time + self.expires_in < time.time()


class Token(NamedTuple):
    access_token: Text
    refresh_token: Text
    scope: Text
    issued_at: int
    expires_in: int
    client_id: Text
    token_type: Text = "Bearer"
    revoked: bool = False

    @property
    def is_expired(self) -> bool:
        return self.token_expires_in < time.time()

    @property
    def refresh_token_expires_in(self) -> int:
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at

    @property
    def token_expires_in(self) -> int:
        expires_at = self.issued_at + self.expires_in
        return expires_at

    @property
    def refresh_token_expired(self) -> bool:
        return self.refresh_token_expires_in < time.time()
