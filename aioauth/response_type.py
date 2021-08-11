"""
.. code-block:: python

    from aioauth import responses

Response objects used throughout the project.
---------------------------------------------
"""

from .storage import BaseStorage
from .errors import (
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnsupportedResponseTypeError,
)
from .models import Client
from .requests import Request
from .responses import (
    AuthorizationCodeResponse,
    IdTokenResponse,
    NoneResponse,
    TokenResponse,
)
from .types import CodeChallengeMethod


class ResponseTypeBase:
    """Base response type that all other exceptions inherit from."""

    def __init__(self, storage: BaseStorage):
        self.storage = storage

    async def validate_request(self, request: Request) -> Client:
        code_challenge_methods = list(CodeChallengeMethod)

        if not request.query.client_id:
            raise InvalidRequestError(
                request=request, description="Missing client_id parameter."
            )

        client = await self.storage.get_client(
            request=request, client_id=request.query.client_id
        )

        if not client:
            raise InvalidRequestError(
                request=request, description="Invalid client_id parameter value."
            )

        if not request.query.redirect_uri:
            raise InvalidRequestError(
                request=request, description="Mismatching redirect URI."
            )

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRequestError(
                request=request, description="Invalid redirect URI."
            )

        if request.query.code_challenge_method:
            if request.query.code_challenge_method not in code_challenge_methods:
                raise InvalidRequestError(
                    request=request, description="Transform algorithm not supported."
                )

            if not request.query.code_challenge:
                raise InvalidRequestError(
                    request=request, description="Code challenge required."
                )

        if not client.check_response_type(request.query.response_type):
            raise UnsupportedResponseTypeError(request=request)

        if not client.check_scope(request.query.scope):
            raise InvalidScopeError(request=request)

        if not request.user:
            raise InvalidClientError(
                request=request, description="User is not authorized"
            )

        return client


class ResponseTypeToken(ResponseTypeBase):
    """Response type that contains a token."""

    async def create_authorization_response(self, request: Request) -> TokenResponse:
        client = await super().validate_request(request)

        token = await self.storage.create_token(
            request, client.client_id, request.query.scope
        )
        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )


class ResponseTypeAuthorizationCode(ResponseTypeBase):
    """Response type that contains an authorization code."""

    async def create_authorization_response(
        self, request: Request
    ) -> AuthorizationCodeResponse:
        client = await super().validate_request(request)

        authorization_code = await self.storage.create_authorization_code(
            request,
            client.client_id,
            request.query.scope,
            request.query.response_type,
            request.query.redirect_uri,
            request.query.code_challenge_method,
            request.query.code_challenge,
        )
        return AuthorizationCodeResponse(
            code=authorization_code.code,
            scope=authorization_code.scope,
        )


class ResponseTypeIdToken(ResponseTypeBase):
    async def validate_request(self, request: Request) -> Client:
        client = await super().validate_request(request)

        # nonce is required for id_token
        if not request.query.nonce:
            raise InvalidRequestError(
                request=request,
                description="Nonce required for response_type id_token.",
            )
        return client

    async def create_authorization_response(self, request: Request) -> IdTokenResponse:
        client = await self.validate_request(request)

        id_token = await self.storage.get_id_token(
            request,
            client.client_id,
            request.query.scope,
            request.query.response_type,
            request.query.redirect_uri,
            request.query.nonce,  # type: ignore
        )

        return IdTokenResponse(id_token=id_token)


class ResponseTypeNone(ResponseTypeBase):
    async def create_authorization_response(self, request: Request) -> NoneResponse:
        await super().validate_request(request)
        return NoneResponse()
