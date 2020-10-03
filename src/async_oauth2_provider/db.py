"""
async_oauth2_provider.db
~~~~~~~~~~~~~~~~~~~~~~~~

This module contains database interaction interface.
"""

import time
from typing import Optional

from .config import settings
from .models import AuthorizationCode, Client, Token
from .requests import Request
from .utils import generate_token


class DBBase:
    async def create_token(self, request: Request, client: Client) -> Token:
        """Generates Token model instance.

        Generated Token MUST be stored in database.

        Method is used by all core grant types.
        Method is used by response types:
            - ResponseTypeToken
        """
        return Token(
            client_id=client.client_id,
            expires_in=settings.TOKEN_EXPIRES_IN,
            access_token=generate_token(42),
            refresh_token=generate_token(48),
            issued_at=time.time(),
            scope=client.get_allowed_scope(request.post.scope or request.query.scope),
            revoked=False,
        )

    async def get_token(self, request, client_id: str) -> Optional[Token]:
        """Gets existing token from the database

        Method is used by:
            - create_token_introspection_response
        """
        raise NotImplementedError("Method get_token must be implemented")

    async def create_authorization_code(
        self, request: Request, client: Client,
    ) -> AuthorizationCode:
        """Generates AuthorizationCode model instance.

        Generated AuthorizationCode MUST be stored in database.

        Method is used by response types:
            - ResponseTypeAuthorizationCode
        """
        return AuthorizationCode(
            code=generate_token(48),
            client_id=client.client_id,
            redirect_uri=request.query.redirect_uri,
            response_type=request.query.response_type,
            scope=client.get_allowed_scope(request.query.scope),
            auth_time=time.time(),
            code_challenge_method=request.query.code_challenge_method,
            code_challenge=request.query.code_challenge,
        )

    async def get_client(
        self, request: Request, client_id: str, client_secret: Optional[str] = None
    ) -> Optional[Client]:
        """Gets existing Client from database.

        If client doesn't exists in database this method MUST return None
        to indicate to the validator that the requested ``client_id`` does not exist or is invalid.

        Method is used by all core grant types.
        Method is used by all core response types.
        """
        raise NotImplementedError("Method get_client must be implemented")

    async def authenticate(self, request: Request) -> bool:
        """Authenticate user.

        Method is used by grant types:
            - PasswordGrantType
        """
        raise NotImplementedError("Method authenticate must be implemented")

    async def get_authorization_code(
        self, request: Request, client: Client
    ) -> Optional[AuthorizationCode]:
        """Gets existing AuthorizationCode from database.

        If authorization code doesn't exists it MUST return None
        to indicate to the validator that the requested authorization code does not exist or is invalid.

        Method is used by grant types:
            - AuthorizationCodeGrantType
        """
        raise NotImplementedError(
            "Method get_authorization_code must be implemented for AuthorizationCodeGrantType"
        )

    async def delete_authorization_code(
        self, request: Request, authorization_code: AuthorizationCode, client: Client
    ):
        """Deletes authorization code from database.

        Method is used by grant types:
            - AuthorizationCodeGrantType
        """
        raise NotImplementedError(
            "Method delete_authorization_code must be implemented for AuthorizationCodeGrantType"
        )

    async def get_refresh_token(
        self, request: Request, client: Client
    ) -> Optional[Token]:
        """Gets refresh token from database.

        If refresh token doesn't exists in database it MUST return None
        Method is used by grant types:
            - RefreshTokenGrantType
        """
        raise NotImplementedError(
            "Method get_refresh_token must be implemented for RefreshTokenGrantType"
        )

    async def revoke_token(self, request: Request, token: Token) -> None:
        """Revokes token in database.

        This method MUST set `revoked` in True for existing token record.

        Method is used by grant types:
            - RefreshTokenGrantType
        """
        raise NotImplementedError(
            "Method revoke_token must be implemented for RefreshTokenGrantType"
        )
