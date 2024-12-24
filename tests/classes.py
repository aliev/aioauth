import time
import sys

from typing import Dict, List, Optional, Type
from functools import cached_property

from dataclasses import replace, dataclass

from aioauth.config import Settings
from aioauth.grant_type import GrantTypeBase
from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import Request
from aioauth.response_type import ResponseTypeBase
from aioauth.server import AuthorizationServer
from aioauth.storage import (
    BaseStorage,
    CreateAuthorizationCodeArgs,
    CreateTokenArgs,
    GetAuthorizationCodeArgs,
    GetClientArgs,
    GetIdTokenArgs,
    GetTokenArgs,
    RevokeTokenArgs,
)
from aioauth.types import GrantType, ResponseType

if sys.version_info >= (3, 11):
    from typing import Unpack
else:
    from typing_extensions import Unpack


@dataclass(frozen=True)
class User:
    username: str


class Storage(BaseStorage[User]):
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
        self,
        **kwargs: Unpack[GetClientArgs[User]],
    ) -> Optional[Client[User]]:
        client_secret = kwargs.get("client_secret")
        client_id = kwargs["client_id"]

        if client_secret is not None:
            return self._get_by_client_secret(client_id, client_secret)

        return self._get_by_client_id(client_id)

    async def create_token(self, **kwargs: Unpack[CreateTokenArgs[User]]):
        client_id = kwargs["client_id"]
        request = kwargs["request"]
        access_token = kwargs["access_token"]
        refresh_token = kwargs["refresh_token"]
        scope = kwargs["scope"]
        token: Token[User] = Token(
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

    async def revoke_token(self, **kwargs: Unpack[RevokeTokenArgs[User]]) -> None:
        tokens = self.tokens
        refresh_token = kwargs["refresh_token"]
        access_token = kwargs["access_token"]
        for key, token_ in enumerate(tokens):
            if token_.refresh_token == refresh_token:
                tokens[key] = replace(token_, revoked=True)
            elif token_.access_token == access_token:
                tokens[key] = replace(token_, revoked=True)

    async def get_token(self, **kwargs: Unpack[GetTokenArgs[User]]) -> Optional[Token]:
        refresh_token = kwargs["refresh_token"]
        access_token = kwargs["access_token"]
        client_id = kwargs["client_id"]

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

    async def get_user(self, request: Request[User]) -> Optional[User]:
        password = request.post.password
        username = request.post.username

        if username is None or password is None:
            return None

        user_exists = username in self.users and self.users[username] == password

        if user_exists:
            return User(username=username)

    async def create_authorization_code(
        self,
        **kwargs: Unpack[CreateAuthorizationCodeArgs[User]],
    ):
        request = kwargs["request"]
        nonce = kwargs.get("nonce")
        code = kwargs["code"]
        client_id = kwargs["client_id"]
        redirect_uri = kwargs["redirect_uri"]
        response_type = kwargs["response_type"]
        scope = kwargs["scope"]
        code_challenge_method = kwargs["code_challenge_method"]
        code_challenge = kwargs["code_challenge"]
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
        self,
        **kwargs: Unpack[GetAuthorizationCodeArgs[User]],
    ) -> Optional[AuthorizationCode]:
        code = kwargs["code"]
        client_id = kwargs["client_id"]

        for authorization_code in self.authorization_codes:
            if (
                authorization_code.code == code
                and authorization_code.client_id == client_id
            ):
                return authorization_code

    async def delete_authorization_code(
        self,
        **kwargs: Unpack[GetAuthorizationCodeArgs[User]],
    ):
        code = kwargs["code"]
        client_id = kwargs["client_id"]
        authorization_codes = self.authorization_codes
        for authorization_code in authorization_codes:
            if (
                authorization_code.client_id == client_id
                and authorization_code.code == code
            ):
                authorization_codes.remove(authorization_code)

    async def get_id_token(self, **kwargs: Unpack[GetIdTokenArgs[User]]) -> str:
        return "generated id token"


class AuthorizationContext:
    def __init__(
        self,
        clients: Optional[List[Client]] = None,
        grant_types: Optional[Dict[GrantType, Type[GrantTypeBase[User]]]] = None,
        initial_authorization_codes: Optional[List[AuthorizationCode]] = None,
        initial_tokens: Optional[List[Token]] = None,
        response_types: Optional[
            Dict[ResponseType, Type[ResponseTypeBase[User]]]
        ] = None,
        settings: Optional[Settings] = None,
        users: Optional[Dict[str, str]] = None,
    ):
        self.initial_authorization_codes = initial_authorization_codes or []
        self.initial_tokens = initial_tokens or []

        self.clients: List[Client] = clients or []
        self.grant_types = grant_types or {}
        self.response_types = response_types or {}
        self.settings = settings or Settings(INSECURE_TRANSPORT=True)
        self.users = users or {}

    @cached_property
    def server(self) -> AuthorizationServer[User]:
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
