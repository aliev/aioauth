from typing import Optional, Type
from urllib.parse import quote, urlencode

from async_oauth2_provider.db import DBBase
from async_oauth2_provider.exceptions import (
    InvalidClientError,
    InvalidRedirectUriError,
    InvalidResponseTypeError,
    InvalidUsernameOrPasswordError,
    MissingClientIdError,
    MissingPasswordError,
    MissingRedirectUriError,
    MissingResponseTypeError,
    MissingScopeError,
    MissingUsernameError,
)
from async_oauth2_provider.models import Client
from async_oauth2_provider.request_validator import BaseRequestValidator
from async_oauth2_provider.requests import Request
from async_oauth2_provider.responses import AuthorizationCodeResponse, TokenResponse
from async_oauth2_provider.types import RequestMethod, ResponseType
from async_oauth2_provider.utils import safe_uri


class ResponseTypeBase(BaseRequestValidator):
    response_type: ResponseType

    def __init__(
        self, db_class: Type[DBBase] = DBBase,
    ):
        self.db_class = db_class

    async def validate_request(self, request: Request, db: DBBase) -> Client:
        await super().validate_request(request)

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


class ResponseTypeToken(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_TOKEN

    async def get_redirect_uri(self, request: Request) -> Optional[str]:
        client, db = await super().get_redirect_uri(request)

        if request.method == RequestMethod.POST:
            scope = client.get_allowed_scope(request.query.scope)
            token = await db.create_token(client.client_id, scope)

            body = TokenResponse.from_orm(token)
            body_dict = body.dict()
            body_dict["scope"] = scope
            body_dict["state"] = request.query.state
            query_string = urlencode(body_dict, quote_via=quote)
            redirect_uri = f"{request.query.redirect_uri}#{query_string}"

            return safe_uri(redirect_uri)


class ResponseTypeAuthorizationCode(ResponseTypeBase):
    response_type: ResponseType = ResponseType.TYPE_CODE

    async def get_redirect_uri(self, request: Request) -> Optional[str]:
        client, db = await super().get_redirect_uri(request)

        if request.method == RequestMethod.POST:
            scope = client.get_allowed_scope(request.query.scope)
            authorization_code = await db.create_authorization_code(
                client.client_id, scope, self.response_type,
            )

            body = AuthorizationCodeResponse.from_orm(authorization_code)
            body_dict = body.dict()
            body_dict["scope"] = scope
            body_dict["state"] = request.query.state
            query_string = urlencode(body_dict, quote_via=quote)
            redirect_uri = f"{request.query.redirect_uri}?{query_string}"

            return safe_uri(redirect_uri)
