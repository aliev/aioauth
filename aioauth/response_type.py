"""
.. code-block:: python

    from aioauth import responses

Response objects used throughout the project.

----
"""

from typing import Generic, List
from .utils import generate_token
from .errors import (
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnsupportedResponseTypeError,
)
from .models import Client
from .requests import TRequest
from .responses import (
    AuthorizationCodeResponse,
    IdTokenResponse,
    NoneResponse,
    TokenResponse,
)
from .storage import TStorage
from .types import CodeChallengeMethod


class ResponseTypeBase(Generic[TRequest, TStorage]):
    """Base response type that all other exceptions inherit from."""

    def __init__(self, storage: TStorage):
        self.storage = storage

    async def validate_request(self, request: TRequest) -> Client:
        code_challenge_methods: List[CodeChallengeMethod] = ["plain", "S256"]

        if not request.query.client_id:
            raise InvalidRequestError[TRequest](
                request=request, description="Missing client_id parameter."
            )

        client = await self.storage.get_client(
            request=request, client_id=request.query.client_id
        )

        if not client:
            raise InvalidRequestError[TRequest](
                request=request, description="Invalid client_id parameter value."
            )

        if not request.query.redirect_uri:
            raise InvalidRequestError[TRequest](
                request=request, description="Mismatching redirect URI."
            )

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRequestError[TRequest](
                request=request, description="Invalid redirect URI."
            )

        if request.query.code_challenge_method:
            if request.query.code_challenge_method not in code_challenge_methods:
                raise InvalidRequestError[TRequest](
                    request=request, description="Transform algorithm not supported."
                )

            if not request.query.code_challenge:
                raise InvalidRequestError[TRequest](
                    request=request, description="Code challenge required."
                )

        if not client.check_response_type(request.query.response_type):
            raise UnsupportedResponseTypeError[TRequest](request=request)

        if not client.check_scope(request.query.scope):
            raise InvalidScopeError[TRequest](request=request)

        if not request.user:
            raise InvalidClientError[TRequest](
                request=request, description="User is not authorized"
            )

        return client


class ResponseTypeToken(ResponseTypeBase[TRequest, TStorage]):
    """Response type that contains a token."""

    async def create_authorization_response(
        self, request: TRequest, client: Client
    ) -> TokenResponse:
        token = await self.storage.create_token(
            request,
            client.client_id,
            request.query.scope,
            generate_token(42),
            generate_token(48),
        )
        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )


class ResponseTypeAuthorizationCode(ResponseTypeBase[TRequest, TStorage]):
    """Response type that contains an authorization code."""

    async def create_authorization_response(
        self, request: TRequest, client: Client
    ) -> AuthorizationCodeResponse:
        authorization_code = await self.storage.create_authorization_code(
            request,
            client.client_id,
            request.query.scope,
            request.query.response_type,  # type: ignore
            request.query.redirect_uri,
            request.query.code_challenge_method,
            request.query.code_challenge,
            generate_token(42),
        )
        return AuthorizationCodeResponse(
            code=authorization_code.code,
            scope=authorization_code.scope,
        )


class ResponseTypeIdToken(ResponseTypeBase[TRequest, TStorage]):
    async def validate_request(self, request: TRequest) -> Client:
        client = await super().validate_request(request)

        # nonce is required for id_token
        if not request.query.nonce:
            raise InvalidRequestError[TRequest](
                request=request,
                description="Nonce required for response_type id_token.",
            )
        return client

    async def create_authorization_response(
        self, request: TRequest, client: Client
    ) -> IdTokenResponse:
        id_token = await self.storage.get_id_token(
            request,
            client.client_id,
            request.query.scope,
            request.query.response_type,  # type: ignore
            request.query.redirect_uri,
            request.query.nonce,  # type: ignore
        )

        return IdTokenResponse(id_token=id_token)


class ResponseTypeNone(ResponseTypeBase[TRequest, TStorage]):
    async def create_authorization_response(
        self, request: TRequest, client: Client
    ) -> NoneResponse:
        return NoneResponse()
