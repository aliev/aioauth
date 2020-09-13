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
from .types import CodeChallengeMethod
from .utils import generate_token


class DBBase:
    async def create_token(self, request: Request, client: Client) -> Token:
        """Generates Token model instance.

        Generated Token MUST be stored in database.

        :param request: OAuth2 Request instance
        :type request: Request
        :param client: OAuth2 Client model instance
        :type client: Client
        :return: Returns Token model instance
        :rtype: Token

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
            scope=client.get_allowed_scope(request.post.scope),
            revoked=False,
        )

    async def create_authorization_code(
        self, request: Request, client: Client,
    ) -> AuthorizationCode:
        """Generates AuthorizationCode model instance.

        Generated AuthorizationCode MUST be stored in database.

        :param request: OAuth2 Request instance
        :type request: Request
        :param client: OAuth2 Client model instance
        :type client: Client
        :return: AuthorizationCode model instance
        :rtype: AuthorizationCode

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
            code_challenge_method=CodeChallengeMethod.PLAIN,
            state=request.query.state,
        )

    async def get_client(
        self, request: Request, client_id: str, client_secret: Optional[str] = None
    ) -> Optional[Client]:
        """Gets existing Client from database.

        If client doesn't exists in database this method MUST return None
        to indicate to the validator that the requested ``client_id`` does not exist or is invalid.

        :param request: OAuth2 Request instance
        :type request: Request
        :param client_id: requested client_id
        :type client_id: str
        :param client_secret: requested client_secret, defaults to None
        :type client_secret: Optional[str], optional
        :raises NotImplementedError: Method must be implemented by library user.
        :return: returns existing Client model instance if client exists in database.
        :rtype: Optional[Client]

        Method is used by all core grant types.
        Method is used by all core response types.
        """
        raise NotImplementedError("Method get_client must be implemented")

    async def get_user(self, request: Request) -> bool:
        """Ensure the username and password is valid.

        :param request: OAuth2 Request instance
        :type request: Request
        :raises NotImplementedError: Method must be implemented by library user.
        :return: Returns True if users exists in database.
        :rtype: bool

        Method is used by grant types:
            - PasswordGrantType
        Method is used by all core response types.
        """
        raise NotImplementedError("Method get_user must be implemented")

    async def get_authorization_code(
        self, request: Request, client: Client
    ) -> Optional[AuthorizationCode]:
        """Gets existing AuthorizationCode from database.

        If authorization code doesn't exists it MUST return None
        to indicate to the validator that the requested authorization code does not exist or is invalid.

        :param request: OAuth2 Request instance
        :type request: Request
        :param client: OAuth2 Client model instance
        :type client: Client
        :raises NotImplementedError: Method must be implemented by library user.
        :return: Returns AuthorizationCode instance if it exists in database.
        :rtype: Optional[AuthorizationCode]

        Method is used by grant types:
            - AuthorizationCodeGrantType
        """
        raise NotImplementedError(
            "Method get_authorization_code must be implemented for AuthorizationCodeGrantType"
        )

    async def delete_authorization_code(
        self, request: Request, authorization_code: AuthorizationCode
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

        :param request: OAuth2 Request instance
        :type request: Request
        :param token: Token model instance that should be revoked.
        :type token: Token
        :raises NotImplementedError: Method must be implemented by library user.

        Method is used by grant types:
            - RefreshTokenGrantType
        """
        raise NotImplementedError(
            "Method revoke_token must be implemented for RefreshTokenGrantType"
        )
