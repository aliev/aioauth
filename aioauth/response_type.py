"""
Response objects used throughout the project.
```python
from aioauth import responses
```
"""

from typing import Tuple, get_args

from .requests import Request
from .storage import BaseStorage

from .utils import generate_token
from .errors import (
    InvalidClientError,
    InvalidRedirectURIError,
    InvalidRequestError,
    InvalidScopeError,
    UnsupportedResponseTypeError,
)
from .models import Client
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
        state = request.query.state

        code_challenge_methods: Tuple[CodeChallengeMethod, ...] = get_args(
            CodeChallengeMethod
        )

        if not request.query.client_id:
            raise InvalidClientError(
                request=request, description="Missing client_id parameter.", state=state
            )

        client = await self.storage.get_client(
            request=request, client_id=request.query.client_id
        )

        if not client:
            raise InvalidClientError(
                request=request,
                description="Invalid client_id parameter value.",
                state=state,
            )

        if not request.query.redirect_uri:
            raise InvalidRedirectURIError(
                request=request, description="Mismatching redirect URI.", state=state
            )

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRedirectURIError(
                request=request, description="Invalid redirect URI.", state=state
            )

        if request.query.code_challenge_method:
            if request.query.code_challenge_method not in code_challenge_methods:
                raise InvalidRequestError(
                    request=request,
                    description="Transform algorithm not supported.",
                    state=state,
                )

            if not request.query.code_challenge:
                raise InvalidRequestError(
                    request=request, description="Code challenge required.", state=state
                )

        if not client.check_response_type(request.query.response_type):
            raise UnsupportedResponseTypeError(request=request, state=state)

        if not client.check_scope(request.query.scope):
            raise InvalidScopeError(request=request, state=state)

        return client


class ResponseTypeToken(ResponseTypeBase):
    """Response type that contains a token."""

    async def create_authorization_response(
        self, request: Request, client: Client
    ) -> TokenResponse:
        token = await self.storage.create_token(
            request=request,
            client_id=client.client_id,
            scope=request.query.scope,
            access_token=generate_token(42),
            refresh_token=(
                generate_token(48)
                if request.settings.ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT
                else None
            ),
        )
        if not request.settings.ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT:
            return TokenResponse(
                expires_in=token.expires_in,
                access_token=token.access_token,
                scope=token.scope,
                token_type=token.token_type,
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
        self, request: Request, client: Client
    ) -> AuthorizationCodeResponse:
        assert request.query.response_type, (
            "`response_type` cannot be an empty string or `None`. "
            "Please make sure you call `validate_request` before calling this method."
        )
        authorization_code = await self.storage.create_authorization_code(
            client_id=client.client_id,
            code=generate_token(42),
            code_challenge=request.query.code_challenge,
            code_challenge_method=request.query.code_challenge_method,
            nonce=request.query.nonce,
            redirect_uri=request.query.redirect_uri,
            request=request,
            response_type=request.query.response_type,
            scope=request.query.scope,
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
                state=request.query.state,
            )
        return client

    async def create_authorization_response(
        self, request: Request, client: Client
    ) -> IdTokenResponse:
        id_token = await self.storage.get_id_token(
            request=request,
            client_id=client.client_id,
            scope=request.query.scope,
            response_type=request.query.response_type,
            redirect_uri=request.query.redirect_uri,
            nonce=request.query.nonce,
        )

        return IdTokenResponse(id_token=id_token)


class ResponseTypeNone(ResponseTypeBase):
    async def create_authorization_response(
        self, request: Request, client: Client
    ) -> NoneResponse:
        return NoneResponse()
