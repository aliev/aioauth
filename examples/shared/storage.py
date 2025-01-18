"""
Storage Interface Implementations for AioOAuth using SqlModels for Backend
"""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import Request
from aioauth.storage import (
    BaseStorage,
    ClientStorage,
    AuthorizationCodeStorage,
    TokenStorage,
)
from aioauth.types import CodeChallengeMethod, TokenType

from .models import User
from .models import Client as ClientTable
from .models import AuthorizationCode as AuthCodeTable
from .models import Token as TokenTable


class ClientStore(ClientStorage[User]):

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_client(
        self,
        *,
        request: Request[User],
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> Optional[Client[User]]:
        """ """
        sql = select(ClientTable).where(ClientTable.client_id == client_id)
        async with self.session:
            record = (await self.session.exec(sql)).one_or_none()
            if record is None:
                return None
            if client_secret is not None and record.client_secret is not None:
                if client_secret != record.client_secret:
                    return None
        return Client(
            client_id=record.client_id,
            client_secret=record.client_secret or "",
            grant_types=record.grant_types.split(","),  # type: ignore
            response_types=record.response_types.split(","),  # type: ignore
            redirect_uris=record.redirect_uris.split(","),
            scope=record.scope,
        )


class AuthCodeStore(AuthorizationCodeStorage[User]):

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_authorization_code(
        self,
        *,
        request: Request[User],
        client_id: str,
        scope: str,
        response_type: str,
        redirect_uri: str,
        code: str,
        code_challenge_method: Optional[CodeChallengeMethod] = None,
        code_challenge: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> AuthorizationCode:
        """"""
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            auth_time=int(datetime.now(tz=timezone.utc).timestamp()),
            expires_in=300,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            user=request.user,
        )
        record = AuthCodeTable(
            code=auth_code.code,
            client_id=auth_code.client_id,
            redirect_uri=auth_code.redirect_uri,
            response_type=auth_code.response_type,
            scope=auth_code.scope,
            auth_time=auth_code.auth_time,
            expires_in=auth_code.expires_in,
            code_challenge=auth_code.code_challenge,
            code_challenge_method=auth_code.code_challenge_method,
            nonce=auth_code.nonce,
            user_id=request.user.id if request.user else None,
        )
        async with self.session:
            self.session.add(record)
            await self.session.commit()
        return auth_code

    async def get_authorization_code(
        self,
        *,
        request: Request[User],
        client_id: str,
        code: str,
    ) -> Optional[AuthorizationCode]:
        """ """
        async with self.session:
            sql = select(AuthCodeTable).where(AuthCodeTable.client_id == client_id)
            result = (await self.session.exec(sql)).one_or_none()
            if result is not None:
                return AuthorizationCode(
                    code=result.code,
                    client_id=result.client_id,
                    redirect_uri=result.redirect_uri,
                    response_type=result.response_type,
                    scope=result.scope,
                    auth_time=result.auth_time,
                    expires_in=result.expires_in,
                    code_challenge=result.code_challenge,
                    code_challenge_method=result.code_challenge_method,  # type: ignore
                    nonce=result.nonce,
                )

    async def delete_authorization_code(
        self,
        *,
        request: Request[User],
        client_id: str,
        code: str,
    ) -> None:
        """ """
        async with self.session:
            sql = select(AuthCodeTable).where(AuthCodeTable.client_id == client_id)
            result = (await self.session.exec(sql)).one()
            await self.session.delete(result)
            await self.session.commit()


class TokenStore(TokenStorage[User]):

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_token(
        self,
        *,
        request: Request[User],
        client_id: str,
        scope: str,
        access_token: str,
        refresh_token: Optional[str] = None,
    ) -> Token:
        """ """
        token = Token(
            client_id=client_id,
            access_token=access_token,
            refresh_token=refresh_token,
            scope=scope,
            issued_at=int(datetime.now(tz=timezone.utc).timestamp()),
            expires_in=300,
            refresh_token_expires_in=900,
            user=request.user,
        )
        record = TokenTable(
            client_id=token.client_id,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            issued_at=token.issued_at,
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            token_type=token.token_type,
            revoked=token.revoked,
            user_id=token.user.id if token.user else None,
        )
        async with self.session:
            self.session.add(record)
            await self.session.commit()
        return token

    async def get_token(
        self,
        *,
        request: Request[User],
        client_id: str,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[Token]:
        """ """
        sql = select(TokenTable)
        sql = (
            sql.where(TokenTable.refresh_token == refresh_token)
            if token_type == "refresh_token"
            else sql.where(TokenTable.access_token == access_token)
        )
        async with self.session:
            result = (await self.session.exec(sql)).one_or_none()
            if result is not None:
                return Token(
                    client_id=result.client_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    scope=result.scope,
                    issued_at=result.issued_at,
                    expires_in=result.expires_in,
                    refresh_token_expires_in=result.refresh_token_expires_in,
                    user=result.user,
                )

    async def revoke_token(
        self,
        *,
        request: Request[User],
        client_id: str,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> None:
        """ """
        sql = select(TokenTable)
        sql = (
            sql.where(TokenTable.refresh_token == refresh_token)
            if token_type == "refresh_token"
            else sql.where(TokenTable.access_token == access_token)
        )
        async with self.session:
            result = (await self.session.exec(sql)).one()
            await self.session.delete(result)
            await self.session.commit()


class BackendStore(ClientStore, AuthCodeStore, TokenStore, BaseStorage[User]):
    pass
