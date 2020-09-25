from typing import Optional

from .exceptions import (
    InvalidClientError,
    InvalidRedirectUriError,
    InvalidResponseTypeError,
    InvalidUserError,
    MissingClientIdError,
    MissingRedirectUriError,
    MissingResponseTypeError,
)
from .models import Client
from .request_validator import BaseRequestValidator
from .requests import Request
from .responses import AuthorizationCodeResponse, TokenResponse
from .types import RequestMethod, ResponseType


class ResponseTypeBase(BaseRequestValidator):
    response_type: Optional[ResponseType] = None
    allowed_methods = (RequestMethod.GET,)

    async def validate_request(self, request: Request) -> Client:
        await super().validate_request(request)

        if not request.query.response_type:
            raise MissingResponseTypeError()

        if not request.query.client_id:
            raise MissingClientIdError()

        if self.response_type != request.query.response_type:
            raise InvalidResponseTypeError()

        if not request.query.redirect_uri:
            raise MissingRedirectUriError()

        client = await self.db.get_client(request, client_id=request.query.client_id)

        if not client:
            raise InvalidClientError()

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRedirectUriError()

        if not client.check_response_type(request.query.response_type):
            raise InvalidResponseTypeError()

        return client

    async def create_authorization_response(self, request: Request) -> Client:
        client = await self.validate_request(request)

        if not request.user:
            raise InvalidUserError()

        return client


class ResponseTypeToken(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_TOKEN

    async def create_authorization_response(self, request: Request) -> TokenResponse:
        client = await super().create_authorization_response(request)

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

    async def create_authorization_response(
        self, request: Request
    ) -> AuthorizationCodeResponse:
        client = await super().create_authorization_response(request)

        authorization_code = await self.db.create_authorization_code(request, client)
        return AuthorizationCodeResponse(
            code=authorization_code.code, scope=authorization_code.scope,
        )
