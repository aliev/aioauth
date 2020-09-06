from typing import Optional

from async_oauth2_provider.exceptions import (
    InvalidClientError,
    InvalidRedirectUriError,
    InvalidResponseTypeError,
    InvalidUsernameOrPasswordError,
    MissingClientIdError,
    MissingPasswordError,
    MissingRedirectUriError,
    MissingResponseTypeError,
    MissingUsernameError,
)
from async_oauth2_provider.models import Client
from async_oauth2_provider.request_validator import BaseRequestValidator
from async_oauth2_provider.requests import Request
from async_oauth2_provider.responses import AuthorizationCodeResponse, TokenResponse
from async_oauth2_provider.types import RequestMethod, ResponseType


class ResponseTypeBase(BaseRequestValidator):
    response_type: Optional[ResponseType] = None

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

        if request.method == RequestMethod.POST:
            if not request.post.username:
                raise MissingUsernameError()
            if not request.post.password:
                raise MissingPasswordError()

            user = await self.db.get_user(request)

            if not user:
                raise InvalidUsernameOrPasswordError()

        return client


class ResponseTypeToken(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_TOKEN

    async def create_authorization_response(
        self, request: Request
    ) -> Optional[TokenResponse]:
        client = await super().create_authorization_response(request)

        if request.method == RequestMethod.POST:
            token = await self.db.create_token(request, client)
            return TokenResponse.from_orm(token)


class ResponseTypeAuthorizationCode(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_CODE

    async def create_authorization_response(
        self, request: Request
    ) -> Optional[AuthorizationCodeResponse]:
        client = await super().create_authorization_response(request)

        if request.method == RequestMethod.POST:
            authorization_code = await self.db.create_authorization_code(
                request, client
            )
            return AuthorizationCodeResponse.from_orm(authorization_code)
