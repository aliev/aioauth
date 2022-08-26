"""
.. code-block:: python

    from aioauth import storage

Storage helper class for storing and retrieving client and resource
owner information. See the examples on the sidebar to view this in
action.

----
"""

from typing import Optional, Generic, TypeVar
from .types import CodeChallengeMethod, ResponseType, TokenType

from .models import TToken, TClient, TAuthorizationCode
from .requests import TRequest


class BaseStorage(Generic[TToken, TClient, TAuthorizationCode, TRequest]):
    async def create_token(
        self,
        request: TRequest,
        client_id: str,
        scope: str,
        access_token: str,
        refresh_token: str,
    ) -> TToken:
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
        raise NotImplementedError("Method create_token must be implemented")

    async def get_token(
        self,
        request: TRequest,
        client_id: str,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[TToken]:
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
        request: TRequest,
        client_id: str,
        scope: str,
        response_type: ResponseType,
        redirect_uri: str,
        code_challenge_method: Optional[CodeChallengeMethod],
        code_challenge: Optional[str],
        code: str,
    ) -> TAuthorizationCode:
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

    async def get_id_token(
        self,
        request: TRequest,
        client_id: str,
        scope: str,
        response_type: ResponseType,
        redirect_uri: str,
        nonce: str,
    ) -> str:
        """Returns an id_token.
        For more information see `OpenID Connect Core 1.0 incorporating errata set 1 section 2 <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>`_.

        Note:
            Method is used by response type :py:class:`aioauth.response_type.ResponseTypeIdToken`
        """
        raise NotImplementedError("get_id_token must be implemented.")

    async def get_client(
        self, request: TRequest, client_id: str, client_secret: Optional[str] = None
    ) -> Optional[TClient]:
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

    async def authenticate(self, request: TRequest) -> bool:
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
        self, request: TRequest, client_id: str, code: str
    ) -> Optional[TAuthorizationCode]:
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
        self, request: TRequest, client_id: str, code: str
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

    async def revoke_token(self, request: TRequest, refresh_token: str) -> None:
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


TStorage = TypeVar("TStorage", bound=BaseStorage)
