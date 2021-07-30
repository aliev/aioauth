from .base.database import BaseDB
from .errors import (
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnsupportedResponseTypeError,
)
from .models import Client
from .requests import Request
from .responses import AuthorizationCodeResponse, NoneResponse, TokenResponse
from .types import CodeChallengeMethod


class ResponseTypeBase:
    def __init__(self, db: BaseDB):
        self.db = db

    async def validate_request(self, request: Request) -> Client:
        code_challenge_methods = list(CodeChallengeMethod)

        if not request.query.client_id:
            raise InvalidRequestError(
                request=request, description="Missing client_id parameter."
            )

        client = await self.db.get_client(
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
    async def create_authorization_response(self, request: Request) -> TokenResponse:
        client = await super().validate_request(request)

        token = await self.db.create_token(
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
    async def create_authorization_response(
        self, request: Request
    ) -> AuthorizationCodeResponse:
        client = await super().validate_request(request)

        authorization_code = await self.db.create_authorization_code(
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


class ResponseTypeNone(ResponseTypeBase):
    async def create_authorization_response(self, request: Request) -> NoneResponse:
        await super().validate_request(request)
        return NoneResponse()
