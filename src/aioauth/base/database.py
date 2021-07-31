import time
from typing import Optional

from ..models import AuthorizationCode, Client, Token
from ..requests import Request
from ..utils import generate_token


class BaseDB:
    async def create_token(self, request: Request, client_id: str, scope: str) -> Token:
        """Generates Token model instance.

        Generated Token MUST be stored in database.

        Method is used by all core grant types.
        Method is used by response types:
            - ResponseTypeToken
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
        """Store the different fields from the namedtuple into your db"""
        raise NotImplementedError(
            "Token MUST be stored in a db. It is a namedtuple and all of its fields should be stored"
        )

    async def get_token(
        self,
        request: Request,
        client_id: str,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[Token]:
        """Gets existing token from the database

        Method is used by:
            - create_token_introspection_response
        Method is used by grant types:
            - RefreshTokenGrantType
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
        """Generates AuthorizationCode model instance.

        Generated AuthorizationCode MUST be stored in database.

        Method is used by response types:
            - ResponseTypeAuthorizationCode
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
        """Returns token_id"""
        raise NotImplementedError("create_token_id must be implemented.")

    async def save_authorization_code(
        self, authorization_code: AuthorizationCode
    ) -> None:
        raise NotImplementedError(
            "AuthorizationCode MUST be stored in any db. It is a namedtuple and all of its fields should be stored"
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
        self, request: Request, client_id: str, code: str
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
        self, request: Request, client_id: str, code: str
    ) -> None:
        """Deletes authorization code from database.

        Method is used by grant types:
            - AuthorizationCodeGrantType
        """
        raise NotImplementedError(
            "Method delete_authorization_code must be implemented for AuthorizationCodeGrantType"
        )

    async def revoke_token(self, request: Request, refresh_token: str) -> None:
        """Revokes token in database.

        This method MUST set `revoked` in True for existing token record.

        Method is used by grant types:
            - RefreshTokenGrantType
        """
        raise NotImplementedError(
            "Method revoke_token must be implemented for RefreshTokenGrantType"
        )
