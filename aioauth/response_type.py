"""
.. code-block:: python

    from aioauth import responses

Response objects used throughout the project.

----
"""
import sys
from typing import Generic, Tuple

if sys.version_info >= (3, 8):
    from typing import get_args
else:
    from typing_extensions import get_args

from .utils import generate_token
from .errors import (
    InvalidClientError,
    InvalidRedirectURIError,
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
from .storage import AuthorizationCodeStorage, ClientStorage, TokenStorage
from .types import CodeChallengeMethod


class ResponseTypeBase(Generic[TRequest, ClientStorage]):
    """Base response type that all other exceptions inherit from."""

    def __init__(self, storage: ClientStorage):
        self.storage = storage

    async def validate_request(self, request: TRequest) -> Client:
        state = request.query.state

        code_challenge_methods: Tuple[CodeChallengeMethod, ...] = get_args(
            CodeChallengeMethod
        )

        if not request.query.client_id:
            raise InvalidClientError[TRequest](
                request=request, description="Missing client_id parameter.", state=state
            )

        client = await self.storage.get_client(
            request=request, client_id=request.query.client_id
        )

        if not client:
            raise InvalidClientError[TRequest](
                request=request,
                description="Invalid client_id parameter value.",
                state=state,
            )

        if not request.query.redirect_uri:
            raise InvalidRedirectURIError[TRequest](
                request=request, description="Mismatching redirect URI.", state=state
            )

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRedirectURIError[TRequest](
                request=request, description="Invalid redirect URI.", state=state
            )

        if request.query.code_challenge_method:
            if request.query.code_challenge_method not in code_challenge_methods:
                raise InvalidRequestError[TRequest](
                    request=request,
                    description="Transform algorithm not supported.",
                    state=state,
                )

            if not request.query.code_challenge:
                raise InvalidRequestError[TRequest](
                    request=request, description="Code challenge required.", state=state
                )

        if not client.check_response_type(request.query.response_type):
            raise UnsupportedResponseTypeError[TRequest](request=request, state=state)

        if not client.check_scope(request.query.scope):
            raise InvalidScopeError[TRequest](request=request, state=state)

        if not request.user:
            raise InvalidClientError[TRequest](
                request=request, description="User is not authorized", state=state
            )

        return client


class ResponseTypeToken(ResponseTypeBase[TRequest, TokenStorage]):
    """Response type that contains a token."""

    def __init__(self, storage: TokenStorage):
        self.storage = storage

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


class ResponseTypeAuthorizationCode(ResponseTypeBase[TRequest, AuthorizationCodeStorage]):
    """Response type that contains an authorization code."""

    def __init__(self, storage: AuthorizationCodeStorage):
        self.storage = storage

    async def create_authorization_response(
        self, request: TRequest, client: Client
    ) -> AuthorizationCodeResponse:
        authorization_code = await self.storage.create_authorization_code(
            client_id=client.client_id,
            code=generate_token(42),
            code_challenge=request.query.code_challenge,
            code_challenge_method=request.query.code_challenge_method,
            nonce=request.query.nonce,
            redirect_uri=request.query.redirect_uri,
            request=request,
            response_type=request.query.response_type,  # type: ignore
            scope=request.query.scope,
        )
        return AuthorizationCodeResponse(
            code=authorization_code.code,
            scope=authorization_code.scope,
        )


class ResponseTypeIdToken(ResponseTypeBase[TRequest, AuthorizationCodeStorage]):
    def __init__(self, storage: AuthorizationCodeStorage):
        self.storage = storage

    async def validate_request(self, request: TRequest) -> Client:
        client = await super().validate_request(request)

        # nonce is required for id_token
        if not request.query.nonce:
            raise InvalidRequestError[TRequest](
                request=request,
                description="Nonce required for response_type id_token.",
                state=request.query.state,
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
            nonce=request.query.nonce,  # type: ignore
        )

        return IdTokenResponse(id_token=id_token)


class ResponseTypeNone(ResponseTypeBase[TRequest, ClientStorage]):
    async def create_authorization_response(
        self, request: TRequest, client: Client
    ) -> NoneResponse:
        return NoneResponse()
