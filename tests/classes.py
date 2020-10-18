from typing import Dict, Optional

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request

from .models import Defaults


class DB(DBBase):
    storage: Dict
    defaults: Defaults

    async def get_client(
        self, request: Request, client_id: str, client_secret: Optional[str] = None
    ) -> Optional[Client]:
        clients = self.storage.get("clients", [])

        for client in clients:
            if client.client_id == client_id:
                return client

    async def create_token(self, request: Request, client: Client, scope: str) -> Token:
        token = await super().create_token(request, client, scope)
        self.storage["tokens"].append(token)
        return token

    async def get_refresh_token(
        self, request: Request, client: Client
    ) -> Optional[Token]:
        # TODO: Split with get_token
        tokens = self.storage.get("tokens", [])

        for token in tokens:
            if request.post.refresh_token == token.refresh_token:
                return token

    async def revoke_token(self, request: Request, token: Token) -> None:
        tokens = self.storage.get("tokens", [])
        for token in tokens:
            if token.refresh_token == token.refresh_token:
                token.revoked = True

    async def get_token(self, request: Request, client_id: str) -> Optional[Token]:
        tokens = self.storage.get("tokens", [])
        for token in tokens:
            if (
                request.post.token == token.access_token
                and client_id == token.client_id
            ):
                return token

    async def authenticate(self, request: Request) -> Optional[bool]:
        if (
            request.post.username == self.defaults.username
            and request.post.password == self.defaults.password
        ):
            return True

    async def create_authorization_code(
        self, request: Request, client: Client, scope: str
    ) -> AuthorizationCode:
        authorization_code = await super().create_authorization_code(
            request, client, scope
        )
        self.storage["authorization_codes"].append(authorization_code)
        return authorization_code

    async def get_authorization_code(
        self, request: Request, client: Client
    ) -> Optional[AuthorizationCode]:
        authorization_codes = self.storage.get("authorization_codes", [])
        for authorization_code in authorization_codes:
            if (
                authorization_code.code == request.post.code
                and authorization_code.client_id == client.client_id
            ):
                return authorization_code

    async def delete_authorization_code(
        self, request: Request, authorization_code: AuthorizationCode, client: Client,
    ):
        authorization_codes = self.storage.get("authorization_codes", [])
        for authorization_code in authorization_codes:
            if (
                authorization_code.client_id == client.client_id
                and authorization_code.code == request.post.code
            ):
                authorization_codes.remove(authorization_code)


def get_db_class(defaults: Defaults, storage: Dict):
    DB.storage = storage
    DB.defaults = defaults
    return DB
