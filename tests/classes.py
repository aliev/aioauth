from typing import Dict, Optional

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request
from async_oauth2_provider.types import CodeChallengeMethod, ResponseType

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

    async def create_token(self, request: Request, client_id: str, scope: str) -> Token:
        token = await super().create_token(request, client_id, scope)
        self.storage["tokens"].append(token)
        return token

    async def get_refresh_token(
        self, request: Request, client_id: str, refresh_token: str
    ) -> Optional[Token]:
        # TODO: Split with get_token
        tokens = self.storage.get("tokens", [])

        for token in tokens:
            if refresh_token == token.refresh_token:
                return token

    async def revoke_token(self, request: Request, token: str) -> None:
        tokens = self.storage.get("tokens", [])
        for token_ in tokens:
            if token_.refresh_token == token:
                token_.revoked = True

    async def get_token(
        self,
        request: Request,
        client_id: str,
        token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[Token]:
        tokens = self.storage.get("tokens", [])
        for token_ in tokens:
            if (
                refresh_token is not None
                and refresh_token == token_.refresh_token
                and client_id == token_.client_id
            ):
                return token_
            if (
                token is not None
                and token == token_.access_token
                and client_id == token_.client_id
            ):
                return token_

    async def authenticate(self, request: Request) -> Optional[bool]:
        if (
            request.post.username == self.defaults.username
            and request.post.password == self.defaults.password
        ):
            return True

    async def create_authorization_code(
        self,
        request: Request,
        client_id: str,
        scope: str,
        response_type: ResponseType,
        redirect_uri: str,
        code_challenge_method: CodeChallengeMethod,
        code_challenge: str,
    ) -> AuthorizationCode:
        authorization_code = await super().create_authorization_code(
            request,
            client_id,
            scope,
            response_type,
            redirect_uri,
            code_challenge_method,
            code_challenge,
        )
        self.storage["authorization_codes"].append(authorization_code)
        return authorization_code

    async def get_authorization_code(
        self, request: Request, client_id: str, code: str
    ) -> Optional[AuthorizationCode]:
        authorization_codes = self.storage.get("authorization_codes", [])
        for authorization_code in authorization_codes:
            if (
                authorization_code.code == code
                and authorization_code.client_id == client_id
            ):
                return authorization_code

    async def delete_authorization_code(
        self, request: Request, client_id: str, code: str,
    ):
        authorization_codes = self.storage.get("authorization_codes", [])
        for authorization_code in authorization_codes:
            if (
                authorization_code.client_id == client_id
                and authorization_code.code == code
            ):
                authorization_codes.remove(authorization_code)


def get_db_class(defaults: Defaults, storage: Dict):
    DB.storage = storage
    DB.defaults = defaults
    return DB
