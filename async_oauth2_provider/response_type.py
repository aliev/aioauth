from typing import Optional, Type, Union

from models import AuthorizationCodeModel, ClientModel, TokenModel
from async_oauth2_provider.exceptions import (
    HTTPMethodNotAllowed, InsecureTransportError,
    InvalidClientException,
    InvalidRedirectUri,
    InvalidResponseTypeException,
    InvalidUsernameOrPasswordException,
    MissingClientIdException,
    MissingPasswordException,
    MissingRedirectUri,
    MissingResponseTypeException,
    MissingScopeException,
    MissingUsernameException,
)

from async_oauth2_provider.utils import is_secure_transport
from async_oauth2_provider.requests import Request

from async_oauth2_provider.request_validators import BaseRequestValidator
from async_oauth2_provider.types import RequestType, ResponseType


class ResponseTypeBase:
    response_type: ResponseType
    request_validator_class: Type[BaseRequestValidator] = BaseRequestValidator
    allowed_methods = (RequestType.METHOD_GET, RequestType.METHOD_POST,)

    def __init__(
        self, request_validator_class: Type[BaseRequestValidator] = None,
    ):
        if request_validator_class is not None:
            self.request_validator_class = request_validator_class

    async def validate_request(
        self, request: Request, request_validator: BaseRequestValidator
    ) -> ClientModel:
        if not is_secure_transport(request.url):
            raise InsecureTransportError()

        if request.method not in self.allowed_methods:
            raise HTTPMethodNotAllowed()

        if not request.query.client_id:
            raise MissingClientIdException()

        if not request.query.response_type:
            raise MissingResponseTypeException()

        if self.response_type != request.query.response_type:
            raise InvalidResponseTypeException()

        if not request.query.redirect_uri:
            raise MissingRedirectUri()

        if not request.query.scope:
            raise MissingScopeException()

        client = await request_validator.get_client(client_id=request.query.client_id)

        if not client:
            raise InvalidClientException()

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRedirectUri()

        if not client.check_response_type(request.query.response_type.value):
            raise InvalidResponseTypeException()

        return client

    def get_request_validator(self, request: Request):
        return self.request_validator_class(request)

    async def create(self, request: Request):
        request_validator = self.get_request_validator(request)
        client = await self.validate_request(request, request_validator)

        if request.method == RequestType.METHOD_POST:
            if not request.post.username:
                raise MissingUsernameException()
            if not request.post.password:
                raise MissingPasswordException()

            user = await request_validator.get_user(
                request.post.username, request.post.password
            )

            if not user:
                raise InvalidUsernameOrPasswordException()

        return client


class ResponseTypeToken(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_TOKEN

    async def create(self, request: Request) -> Optional[TokenModel]:
        client = await super().create(request)
        request_validator = self.get_request_validator(request)

        if request.method == RequestType.METHOD_POST:
            return await request_validator.create_token(client.client_id)


class ResponseTypeAuthorizationCode(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_CODE

    async def create(self, request: Request) -> Optional[AuthorizationCodeModel]:
        client = await super().create(request)
        request_validator = self.get_request_validator(request)

        if request.method == RequestType.METHOD_POST:
            return await request_validator.create_authorization_code(client.client_id)