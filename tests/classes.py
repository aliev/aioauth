import time
from typing import NamedTuple

from dataclasses import replace, dataclass, field
from typing import List, Optional

from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import BaseRequest, Post, Query
from aioauth.storage import BaseStorage
from aioauth.types import CodeChallengeMethod, TokenType


class BasicServerConfig(NamedTuple):
    client_id: str
    client_secret: str
    code: str
    refresh_token: str
    access_token: str
    username: str
    password: str
    redirect_uri: str
    scope: str


@dataclass
class User:
    first_name: str
    last_name: str


@dataclass
class Request(BaseRequest[Query, Post, User]):
    ...


@dataclass
class StorageConfig:
    server_config: BasicServerConfig
    authorization_codes: List[AuthorizationCode] = field(default_factory=list)
    clients: List[Client] = field(default_factory=list)
    tokens: List[Token] = field(default_factory=list)


class Storage(BaseStorage[Token, Client, AuthorizationCode, Request]):
    def __init__(self, config: StorageConfig):
        self.config: StorageConfig = config

    def _get_by_client_secret(self, client_id: str, client_secret: str):
        for client in self.config.clients:
            if client.client_id == client_id and client.client_secret == client_secret:
                return client

    def _get_by_client_id(self, client_id: str):
        for client in self.config.clients:
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
        self.config.tokens.append(token)
        return token

    async def revoke_token(self, request: Request, refresh_token: str) -> None:
        tokens = self.config.tokens
        for key, token_ in enumerate(tokens):
            if token_.refresh_token == refresh_token:
                tokens[key] = replace(token_, revoked=True)

    async def get_token(
        self,
        request: Request,
        client_id: str,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[Token]:
        for token_ in self.config.tokens:
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
        if (
            request.post.username == self.config.server_config.username
            and request.post.password == self.config.server_config.password
        ):
            return True

        return False

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
    ):
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
        )
        self.config.authorization_codes.append(authorization_code)

        return authorization_code

    async def get_authorization_code(
        self, request: Request, client_id: str, code: str
    ) -> Optional[AuthorizationCode]:
        for authorization_code in self.config.authorization_codes:
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
        authorization_codes = self.config.authorization_codes
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
    ) -> str:
        return "generated id token"
