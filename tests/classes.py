import time
import sys

from typing import Any, Dict, List, Optional

from dataclasses import replace, dataclass

from aioauth.config import Settings
from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import BaseRequest, Post, Query, TRequest
from aioauth.server import AuthorizationServer
from aioauth.storage import TokenStorage, AuthorizationCodeStorage, ClientStorage, UserStorage
from aioauth.types import CodeChallengeMethod, GrantType, ResponseType, TokenType

if sys.version_info >= (3, 8):
    from functools import cached_property
else:
    from backports.cached_property import cached_property


@dataclass
class User:
    first_name: str
    last_name: str


@dataclass
class Request(BaseRequest[Query, Post, User]):
    ...


class Storage(TokenStorage[Token, Request], AuthorizationCodeStorage[AuthorizationCode, Request], ClientStorage[Client, Request], UserStorage[Request]):
    def __init__(
        self,
        authorization_codes: List[AuthorizationCode],
        clients: List[Client],
        tokens: List[Token],
        users: Dict[str, str] = {},
    ):
        self.clients: List[Client] = clients
        self.tokens: List[Token] = tokens
        self.authorization_codes: List[AuthorizationCode] = authorization_codes
        self.users: Dict[str, str] = users

    def _get_by_client_secret(self, client_id: str, client_secret: str):
        for client in self.clients:
            if client.client_id == client_id and client.client_secret == client_secret:
                return client

    def _get_by_client_id(self, client_id: str):
        for client in self.clients:
            if client.client_id == client_id:
                return client

    async def get_client(
        self, request: Request, client_id: str, client_secret: Optional[str] = None
    ) -> Optional[Client]:
        if client_secret is not None:
            return self._get_by_client_secret(client_id, client_secret)

        return self._get_by_client_id(client_id)

    async def create_token(
        self,
        request: Request,
        client_id: str,
        scope: str,
        access_token: str,
        refresh_token: str,
    ):
        token = Token(
            client_id=client_id,
            expires_in=request.settings.TOKEN_EXPIRES_IN,
            refresh_token_expires_in=request.settings.REFRESH_TOKEN_EXPIRES_IN,
            access_token=access_token,
            refresh_token=refresh_token,
            issued_at=int(time.time()),
            scope=scope,
            revoked=False,
        )
        self.tokens.append(token)
        return token

    async def revoke_token(
        self,
        request: Request,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> None:
        tokens = self.tokens
        for key, token_ in enumerate(tokens):
            if token_.refresh_token == refresh_token:
                tokens[key] = replace(token_, revoked=True)
            elif token_.access_token == access_token:
                tokens[key] = replace(token_, revoked=True)

    async def get_token(
        self,
        request: Request,
        client_id: str,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[Token]:
        for token_ in self.tokens:
            if (
                refresh_token is not None
                and refresh_token == token_.refresh_token
                and client_id == token_.client_id
            ):
                return token_
            if (
                access_token is not None
                and access_token == token_.access_token
                and client_id == token_.client_id
            ):
                return token_

    async def authenticate(self, request: Request) -> bool:
        password = request.post.password
        username = request.post.username
        return username in self.users and self.users[username] == password

    async def create_authorization_code(
        self,
        request: Request,
        client_id: str,
        scope: str,
        response_type: str,
        redirect_uri: str,
        code_challenge_method: Optional[CodeChallengeMethod],
        code_challenge: Optional[str],
        code: str,
        **kwargs,
    ):
        nonce = kwargs.get("nonce")
        authorization_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            auth_time=int(time.time()),
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
            expires_in=request.settings.AUTHORIZATION_CODE_EXPIRES_IN,
            nonce=nonce,
        )
        self.authorization_codes.append(authorization_code)

        return authorization_code

    async def get_authorization_code(
        self, request: Request, client_id: str, code: str
    ) -> Optional[AuthorizationCode]:
        for authorization_code in self.authorization_codes:
            if (
                authorization_code.code == code
                and authorization_code.client_id == client_id
            ):
                return authorization_code

    async def delete_authorization_code(
        self,
        request: Request,
        client_id: str,
        code: str,
    ):
        authorization_codes = self.authorization_codes
        for authorization_code in authorization_codes:
            if (
                authorization_code.client_id == client_id
                and authorization_code.code == code
            ):
                authorization_codes.remove(authorization_code)

    async def get_id_token(
        self,
        request: Request,
        client_id: str,
        scope: str,
        response_type: str,
        redirect_uri: str,
        nonce: str,
        **kwargs,
    ) -> str:
        return "generated id token"


class AuthorizationContext:
    def __init__(
        self,
        clients: Optional[List[Client]] = None,
        grant_types: Optional[Dict[GrantType, Any]] = None,
        initial_authorization_codes: Optional[List[AuthorizationCode]] = None,
        initial_tokens: Optional[List[Token]] = None,
        response_types: Optional[Dict[ResponseType, Any]] = None,
        settings: Optional[Settings] = None,
        users: Dict[str, str] = None,
    ):
        self.initial_authorization_codes = initial_authorization_codes or []
        self.initial_tokens = initial_tokens or []

        self.clients: List[Client] = clients or []
        self.grant_types = grant_types or {}
        self.response_types = response_types or {}
        self.settings = settings or Settings(INSECURE_TRANSPORT=True)
        self.users = users or {}

    @cached_property
    def server(self) -> AuthorizationServer[TRequest, Storage]:
        return AuthorizationServer(
            grant_types=self.grant_types,
            response_types=self.response_types,
            storage=self.storage,
        )

    @cached_property
    def storage(self) -> Storage:
        return Storage(
            authorization_codes=self.initial_authorization_codes,
            clients=self.clients,
            tokens=self.initial_tokens,
            users=self.users,
        )
