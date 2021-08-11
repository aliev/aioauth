"""
.. code-block:: python

    from aioauth import storage

Storage helper class for storing and retrieving client and resource
owner information. See the examples on the sidebar to view this in
action.
----
"""

import time
from typing import Optional

from .models import AuthorizationCode, Client, Token
from .requests import Request
from .utils import generate_token


class BaseStorage:
    async def create_token(self, request: Request, client_id: str, scope: str) -> Token:
        """Generates a user token and stores it in the database.
        Warning:
            Generated token *must* be stored in the database.
        Note:
            Method is used by all core grant types, but only used for
            :py:class:`aioauth.response_type.ResponseTypeToken`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
            client_id: A user client ID.
            scope: The scopes for the token.
        Returns:
            The new generated :py:class:`aioauth.models.Token`.
        """
        token = Token(
            client_id=client_id,
            expires_in=request.settings.TOKEN_EXPIRES_IN,
            access_token=generate_token(42),
            refresh_token=generate_token(48),
            issued_at=int(time.time()),
            scope=scope,
            revoked=False,
        )
        await self.save_token(token)
        return token

    async def save_token(self, token: Token) -> None:
        """Store the different fields from the namedtuple into your storage"""
        raise NotImplementedError(
            "Token MUST be stored in a storage. It is a namedtuple and all of its fields should be stored"
        )

    async def get_token(
        self,
        request: Request,
        client_id: str,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[Token]:
        """Gets existing token from the database.
        Note:
            Method is used by
            :py:class:`aioauth.server.AuthorizationServer`,  and by the
            grant type :py:class:`aioauth.grant_types.RefreshTokenGrantType`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
            client_id: A user client ID.
            access_token: The user access token.
            refresh_token: The user refresh token.
        Returns:
            An optional :py:class:`aioauth.models.Token` object.
        """
        raise NotImplementedError("Method get_token must be implemented")

    async def create_authorization_code(
        self,
        request: Request,
        client_id: str,
        scope: str,
        response_type: str,
        redirect_uri: str,
        code_challenge_method: Optional[str],
        code_challenge: Optional[str],
    ) -> AuthorizationCode:
        """Generates an authorization token and stores it in the database.
        Warning:
            Generated authorization token *must* be stored in the database.
        Note:
            This must is used by the response type
            :py:class:`aioauth.respose_type.ResponseTypeAuthorizationCode`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
            client_id: A user client ID.
            scope: The scopes for the token.
            response_type: An :py:class:`aioauth.types.ResponseType`.
            redirect_uri: The redirect URI.
            code_challenge_method: An :py:class:`aioauth.types.CodeChallengeMethod`.
            code_challenge: Code challenge string.
        Returns:
            An :py:class:`aioauth.models.AuthorizationCode` object.
        """
        authorization_code = AuthorizationCode(
            code=generate_token(48),
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            auth_time=int(time.time()),
            code_challenge_method=code_challenge_method,
            code_challenge=code_challenge,
            expires_in=request.settings.AUTHORIZATION_CODE_EXPIRES_IN,
        )
        await self.save_authorization_code(authorization_code)
        return authorization_code

    async def get_id_token(
        self,
        request: Request,
        client_id: str,
        scope: str,
        response_type: str,
        redirect_uri: str,
        nonce: str,
    ) -> str:
        """Returns token_id. Required for OpenID.

        Method is used by response types:
            - ResponseTypeIdToken
        """
        raise NotImplementedError("create_token_id must be implemented.")

    async def save_authorization_code(
        self, authorization_code: AuthorizationCode
    ) -> None:
        raise NotImplementedError(
            "AuthorizationCode MUST be stored in any storage. It is a namedtuple and all of its fields should be stored"
        )

    async def get_client(
        self, request: Request, client_id: str, client_secret: Optional[str] = None
    ) -> Optional[Client]:
        """Gets existing client from the database if it exists.
        Warning:
            If client does not exists in database this method *must*
            return ``None`` to indicate to the validator that the
            requested ``client_id`` does not exist or is invalid.
        Note:
            This method is used by all core grant types, as well as
            all core response types.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
            client_id: A user client ID.
            client_secret: An optional user client secret.
        Returns:
            An optional :py:class:`aioauth.models.Client` object.
        """
        raise NotImplementedError("Method get_client must be implemented")

    async def authenticate(self, request: Request) -> bool:
        """Authenticates a user.
        Note:
            This method is used by the grant type
            :py:class:`aioauth.grant_type.PasswordGrantType`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
        Returns:
            Boolean indicating whether or not the user was authenticated
            successfully.
        """
        raise NotImplementedError("Method authenticate must be implemented")

    async def get_authorization_code(
        self, request: Request, client_id: str, code: str
    ) -> Optional[AuthorizationCode]:
        """Gets existing authorization code from the database if it exists.
        Warning:
            If authorization code does not exists this function *must*
            return ``None`` to indicate to the validator that the
            requested authorization code does not exist or is invalid.
        Note:
            This method is used by the grant type
            :py:class:`aioauth.grant_type.AuthorizationCodeGrantType`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
            client_id: A user client ID.
            code: An authorization code.
        Returns:
            An optional :py:class:`aioauth.models.AuthorizationCode`.
        """
        raise NotImplementedError(
            "Method get_authorization_code must be implemented for AuthorizationCodeGrantType"
        )

    async def delete_authorization_code(
        self, request: Request, client_id: str, code: str
    ) -> None:
        """Deletes authorization code from database.
        Note:
            This method is used by the grant type
            :py:class:`aioauth.grant_type.AuthorizationCodeGrantType`.
        Args:
            An :py:class:`aioauth.requests.Request`.
            client_id: A user client ID.
            code: An authorization code.
        """
        raise NotImplementedError(
            "Method delete_authorization_code must be implemented for AuthorizationCodeGrantType"
        )

    async def revoke_token(self, request: Request, refresh_token: str) -> None:
        """Revokes a token's from the database.
        Note:
            This method *must* set ``revoked`` to ``True`` for an
            existing token record. This method is used by the grant type
            :py:class:`aioauth.grant_types.RefreshTokenGrantType`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
            refresh_token: The user refresh token.
        """
        raise NotImplementedError(
            "Method revoke_token must be implemented for RefreshTokenGrantType"
        )
