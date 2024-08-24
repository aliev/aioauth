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


class TokenStorage(Generic[TToken, TRequest]):
    async def create_token(
        self,
        request: TRequest,
        client_id: str,
        scope: str,
        access_token: str,
        refresh_token: str,
    ) -> TToken:
        raise NotImplementedError("Method create_token must be implemented")

    async def get_token(
        self,
        request: TRequest,
        client_id: str,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[TToken]:
        raise NotImplementedError("Method get_token must be implemented")

    async def revoke_token(
        self,
        request: TRequest,
        token_type: Optional[TokenType] = "refresh_token",
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> None:
        raise NotImplementedError("Method revoke_token must be implemented")


class AuthorizationCodeStorage(Generic[TAuthorizationCode, TRequest]):
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
        **kwargs,
    ) -> TAuthorizationCode:
        raise NotImplementedError(
            "Method create_authorization_code must be implemented"
        )

    async def get_authorization_code(
        self, request: TRequest, client_id: str, code: str
    ) -> Optional[TAuthorizationCode]:
        raise NotImplementedError(
            "Method get_authorization_code must be implemented for AuthorizationCodeGrantType"
        )

    async def delete_authorization_code(
        self, request: TRequest, client_id: str, code: str
    ) -> None:
        raise NotImplementedError(
            "Method delete_authorization_code must be implemented for AuthorizationCodeGrantType"
        )


class ClientStorage(Generic[TClient, TRequest]):
    async def get_client(
        self, request: TRequest, client_id: str, client_secret: Optional[str] = None
    ) -> Optional[TClient]:
        raise NotImplementedError("Method get_client must be implemented")


class UserStorage(Generic[TRequest]):
    async def authenticate(self, request: TRequest) -> bool:
        raise NotImplementedError("Method authenticate must be implemented")


TStorage = TypeVar("TStorage", bound=TokenStorage)
TStorage = TypeVar("TStorage", bound=AuthorizationCodeStorage)
TStorage = TypeVar("TStorage", bound=ClientStorage)
TStorage = TypeVar("TStorage", bound=UserStorage)
