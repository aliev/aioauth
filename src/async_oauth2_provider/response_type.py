from typing import Optional

from .exceptions import (
    InvalidRequestError,
    InvalidUserError,
    UnsupportedResponseTypeError,
)
from .models import Client
from .request_validator import BaseRequestValidator
from .requests import Request
from .responses import AuthorizationCodeResponse, TokenResponse
from .types import CodeChallengeMethod, RequestMethod, ResponseType


class ResponseTypeBase(BaseRequestValidator):
    response_type: Optional[ResponseType] = None
    allowed_methods = [
        RequestMethod.GET,
    ]
    code_challenge_methods = list(CodeChallengeMethod)

    async def validate_request(self, request: Request) -> Client:
        await super().validate_request(request)

        if not request.query.response_type:
            raise InvalidRequestError(
                request=request, description="Missing response_type parameter."
            )

        if not request.query.client_id:
            raise InvalidRequestError(
                request=request, description="Missing client_id parameter."
            )

        if self.response_type != request.query.response_type:
            raise UnsupportedResponseTypeError(request=request)

        if not request.query.redirect_uri:
            raise InvalidRequestError(
                request=request, description="Mismatching redirect URI."
            )

        client = await self.db.get_client(
            request=request, client_id=request.query.client_id
        )

        if not client:
            raise InvalidRequestError(
                request=request, description="Invalid client_id parameter value."
            )

        if request.query.code_challenge_method:
            if request.query.code_challenge_method not in self.code_challenge_methods:
                raise InvalidRequestError(
                    request=request, description="Transform algorithm not supported."
                )

            if not request.query.code_challenge:
                raise InvalidRequestError(
                    request=request, description="Code challenge required."
                )

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRequestError(
                request=request, description="Invalid redirect URI."
            )

        if not client.check_response_type(request.query.response_type):
            raise UnsupportedResponseTypeError(request=request)

        return client

    async def create_authorization_code_response(self, request: Request) -> Client:
        client = await self.validate_request(request)

        if not request.user:
            raise InvalidUserError(request=request)

        return client


class ResponseTypeToken(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_TOKEN

    async def create_authorization_code_response(
        self, request: Request
    ) -> TokenResponse:
        client = await super().create_authorization_code_response(request)

        token = await self.db.create_token(request, client)
        return TokenResponse(
            expires_in=token.expires_in,
            refresh_token_expires_in=token.refresh_token_expires_in,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            scope=token.scope,
            token_type=token.token_type,
        )


class ResponseTypeAuthorizationCode(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_CODE

    async def create_authorization_code_response(
        self, request: Request
    ) -> AuthorizationCodeResponse:
        client = await super().create_authorization_code_response(request)

        authorization_code = await self.db.create_authorization_code(request, client)
        return AuthorizationCodeResponse(
            code=authorization_code.code, scope=authorization_code.scope,
        )
