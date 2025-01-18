"""
.. code-block:: python

    from aioauth import storage

Storage helper class for storing and retrieving client and resource
owner information. See the examples on the sidebar to view this in
action.

----
"""

from typing import Optional, Generic

from .models import AuthorizationCode, Client, Token
from .types import CodeChallengeMethod, TokenType

from .requests import Request
from .types import UserType


class TokenStorage(Generic[UserType]):
    async def create_token(
        self,
        *,
        request: Request[UserType],
        client_id: str,
        scope: str,
        access_token: str,
        refresh_token: Optional[str] = None,
    ) -> Token:
        """Generates a user token and stores it in the database.

        Used by:
            - `ResponseTypeToken`
            - `AuthorizationCodeGrantType`
            - `PasswordGrantType`
            - `ClientCredentialsGrantType`
            - `RefreshTokenGrantType`

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
        raise NotImplementedError("Method create_token must be implemented")

    async def get_token(
        self,
        *,
        request: Request[UserType],
        client_id: str,
        token_type: Optional[TokenType] = None,
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

    async def revoke_token(
        self,
        *,
        request: Request[UserType],
        client_id: str,
        refresh_token: Optional[str] = None,
        token_type: Optional[TokenType] = None,
        access_token: Optional[str] = None,
    ) -> None:
        """Revokes a token from the database."""
        raise NotImplementedError


class AuthorizationCodeStorage(Generic[UserType]):
    async def create_authorization_code(
        self,
        *,
        request: Request[UserType],
        client_id: str,
        scope: str,
        response_type: str,
        redirect_uri: str,
        code: str,
        code_challenge_method: Optional[CodeChallengeMethod] = None,
        code_challenge: Optional[str] = None,
        nonce: Optional[str] = None,
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
        raise NotImplementedError(
            "Method create_authorization_code must be implemented"
        )

    async def get_authorization_code(
        self,
        *,
        request: Request[UserType],
        client_id: str,
        code: str,
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
        self,
        *,
        request: Request[UserType],
        client_id: str,
        code: str,
    ) -> None:
        """Deletes authorization code from database.

        Note:
            This method is used by the grant type
            :py:class:`aioauth.grant_type.AuthorizationCodeGrantType`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
            client_id: A user client ID.
            code: An authorization code.
        """
        raise NotImplementedError(
            "Method delete_authorization_code must be implemented for AuthorizationCodeGrantType"
        )


class ClientStorage(Generic[UserType]):
    async def get_client(
        self,
        *,
        request: Request[UserType],
        client_id: str,
        client_secret: Optional[str] = None,
    ) -> Optional[Client[UserType]]:
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


class UserStorage(Generic[UserType]):
    async def get_user(self, request: Request[UserType]) -> Optional[UserType]:
        """Returns a user.

        Note:
            This method is used by the grant type
            :py:class:`aioauth.grant_type.PasswordGrantType`.
        Args:
            request: An :py:class:`aioauth.requests.Request`.
        Returns:
            Boolean indicating whether or not the user was authenticated
            successfully.
        """
        raise NotImplementedError("Method get_user must be implemented")


class IDTokenStorage(Generic[UserType]):
    async def get_id_token(
        self,
        *,
        request: Request[UserType],
        client_id: str,
        scope: str,
        redirect_uri: str,
        response_type: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> str:
        """Returns an id_token.
        For more information see `OpenID Connect Core 1.0 incorporating errata set 1 section 2 <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>`_.

        Note:
            Method is used by response type :py:class:`aioauth.response_type.ResponseTypeIdToken`
            and :py:class:`aioauth.oidc.core.grant_type.AuthorizationCodeGrantType`.
        """
        raise NotImplementedError("get_id_token must be implemented.")


class BaseStorage(
    Generic[UserType],
    TokenStorage[UserType],
    AuthorizationCodeStorage[UserType],
    ClientStorage[UserType],
    UserStorage[UserType],
    IDTokenStorage[UserType],
): ...
