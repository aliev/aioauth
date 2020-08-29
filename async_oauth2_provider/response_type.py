from typing import Optional, Type, Union
from urllib.parse import quote, quote_plus, urlencode

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.exceptions import (
    InsecureTransportError,
    InvalidClientError,
    InvalidRedirectUriError,
    InvalidResponseTypeError,
    InvalidUsernameOrPasswordError,
    MethodNotAllowedError,
    MissingClientIdError,
    MissingPasswordError,
    MissingRedirectUriError,
    MissingResponseTypeError,
    MissingScopeError,
    MissingUsernameError,
)
from async_oauth2_provider.models import AuthorizationCode, Client, Token
from async_oauth2_provider.requests import Request
from async_oauth2_provider.responses import AuthorizationCodeResponse, TokenResponse
from async_oauth2_provider.types import RequestMethod, ResponseType
from async_oauth2_provider.utils import is_secure_transport


class ResponseTypeBase:
    response_type: ResponseType
    allowed_methods = (
        RequestMethod.GET,
        RequestMethod.POST,
    )

    def __init__(
        self, db_class: Type[DBBase] = DBBase,
    ):
        self.db_class = db_class

    async def validate_request(self, request: Request, db: DBBase) -> Client:
        if not is_secure_transport(request.url):
            raise InsecureTransportError()

        if request.method not in self.allowed_methods:
            raise MethodNotAllowedError()

        if not request.query.client_id:
            raise MissingClientIdError()

        if not request.query.response_type:
            raise MissingResponseTypeError()

        if self.response_type != request.query.response_type:
            raise InvalidResponseTypeError()

        if not request.query.redirect_uri:
            raise MissingRedirectUriError()

        if not request.query.scope:
            raise MissingScopeError()

        client = await db.get_client(client_id=request.query.client_id)

        if not client:
            raise InvalidClientError()

        if not client.check_redirect_uri(request.query.redirect_uri):
            raise InvalidRedirectUriError()

        if not client.check_response_type(request.query.response_type):
            raise InvalidResponseTypeError()

        return client

    def get_db(self, request: Request):
        return self.db_class(request)

    async def get_redirect_uri(self, request: Request):
        db = self.get_db(request)
        client = await self.validate_request(request, db)

        if request.method == RequestMethod.POST:
            if not request.post.username:
                raise MissingUsernameError()
            if not request.post.password:
                raise MissingPasswordError()

            user = await db.get_user(request.post.username, request.post.password)

            if not user:
                raise InvalidUsernameOrPasswordError()

        return client, db

    def generate_uri(
        self,
        request: Request,
        response: Union[Type[TokenResponse], Type[AuthorizationCodeResponse]],
        model: Union[AuthorizationCode, Token],
        fragment: str,
    ):
        body = response.from_orm(model)
        body_dict = body.dict()
        body_dict["scope"] = request.query.scope
        body_dict["state"] = request.query.state
        query_string = urlencode(body_dict, quote_via=quote)
        redirect_uri = f"{request.query.redirect_uri}{fragment}{query_string}"
        return quote_plus(str(redirect_uri), safe=":/%#?&=@[]!$&'()*+,;")


class ResponseTypeToken(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_TOKEN

    async def get_redirect_uri(self, request: Request) -> Optional[str]:
        client, db = await super().get_redirect_uri(request)

        if request.method == RequestMethod.POST:
            token = await db.create_token(client.client_id, request.query.scope or "")
            return self.generate_uri(request, TokenResponse, token, "#")


class ResponseTypeAuthorizationCode(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_CODE

    async def get_redirect_uri(self, request: Request) -> Optional[str]:
        client, db = await super().get_redirect_uri(request)

        if request.method == RequestMethod.POST:
            authorization_code = await db.create_authorization_code(
                client.client_id, request.query.scope or "", self.response_type,
            )
            return self.generate_uri(
                request, AuthorizationCodeResponse, authorization_code, "?"
            )
