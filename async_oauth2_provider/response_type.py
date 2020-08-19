from typing import Optional, Type, Union

from models import AuthorizationCodeModel, ClientModel, TokenModel, UserModel
from async_oauth2_provider.exceptions import InsecureTransportError

from async_oauth2_provider.utils import is_secure_transport

from async_oauth2_provider.responses import Response

from async_oauth2_provider.requests import Request

from async_oauth2_provider.request_validators import BaseRequestValidator
from async_oauth2_provider.types import RequestType, ResponseType


class ResponseTypeBase:
    response_type: ResponseType
    request_validator_class: Type[BaseRequestValidator] = BaseRequestValidator

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

        if self.response_type != request.query.response_type:
            raise Exception()

        if not request.query.client_id:
            raise Exception()

        if not request.query.redirect_uri:
            raise Exception()

        if not request.query.response_type:
            raise Exception()

        if not request.query.state:
            raise Exception()

        if not request.query.scope:
            raise Exception()

        client = await request_validator.get_client(client_id=request.query.client_id)

        if not client:
            raise Exception()

        if not client.check_response_type(request.query.response_type):
            raise Exception()

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise Exception()

        return client

    def get_request_validator(self, request: Request):
        return self.request_validator_class(request)

    async def create(self, request: Request):
        request_validator = self.get_request_validator(request)
        client = await self.validate_request(request, request_validator)

        if request.method == RequestType.METHOD_POST:
            if not request.post.username:
                raise Exception()
            if not request.post.password:
                raise Exception()

            user = await request_validator.get_user(
                request.post.username, request.post.password
            )

            if not user:
                raise Exception()

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


class ResponseTypeEndpoint:
    pass
