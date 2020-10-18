from dataclasses import asdict
from http import HTTPStatus
from typing import Dict, Optional, Type, Union

from .constances import default_headers
from .db import DBBase
from .exceptions import OAuth2Exception
from .grant_type import GrantTypeBase
from .requests import Request
from .response_type import ResponseTypeBase
from .responses import (
    ErrorResponse,
    Response,
    TokenActiveIntrospectionResponse,
    TokenInactiveIntrospectionResponse,
)
from .structures import CaseInsensitiveDict
from .types import EndpointType, GrantType, ResponseType
from .utils import build_uri, check_basic_auth


class OAuth2Endpoint:
    response_type: Dict[Optional[ResponseType], Type[ResponseTypeBase]] = {}
    grant_type: Dict[Optional[GrantType], Type[GrantTypeBase]] = {}

    def __init__(self, db: DBBase):
        self.db = db

    def register(
        self,
        endpoint_type: EndpointType,
        endpoint: Union[ResponseType, GrantType],
        endpoint_cls: Union[Type[ResponseTypeBase], Type[GrantTypeBase]],
    ):
        endpoint_dict = getattr(self, endpoint_type)
        endpoint_dict[endpoint] = endpoint_cls

    def unregister(
        self, endpoint_type: EndpointType, endpoint: Union[ResponseType, GrantType]
    ):
        endpoint_dict = getattr(self, endpoint_type)
        del endpoint_dict[endpoint]

    async def create_token_introspection_response(self, request: Request) -> Response:
        client_id, client_secret = check_basic_auth(request)

        token = await self.db.get_token(
            request=request, client_id=client_id, token=request.post.token
        )

        content = TokenInactiveIntrospectionResponse()
        if token:
            content = TokenActiveIntrospectionResponse(
                scope=token.scope, client_id=token.client_id, exp=token.expires_in
            )

        return Response(
            content=content, status_code=HTTPStatus.OK, headers=default_headers
        )

    async def create_token_response(self, request: Request) -> Response:
        grant_type_cls = self.grant_type.get(request.post.grant_type, GrantTypeBase)
        grant_type_handler = grant_type_cls(self.db)

        status_code = HTTPStatus.OK
        headers = default_headers
        content = None

        try:
            content = await grant_type_handler.create_token_response(request)
        except OAuth2Exception as exc:
            status_code = exc.status_code
            headers = exc.headers
            content = ErrorResponse(error=exc.error, description=exc.description)

        return Response(content=content, status_code=status_code, headers=headers)

    async def create_authorization_code_response(self, request: Request) -> Response:
        response_type_cls = self.response_type.get(
            request.query.response_type, ResponseTypeBase
        )
        response_type_handler = response_type_cls(self.db)

        status_code = HTTPStatus.FOUND
        headers = default_headers
        content = None

        try:
            response = await response_type_handler.create_authorization_code_response(
                request
            )
            response_type = request.query.response_type
            response_dict = {**asdict(response), "state": request.query.state}
            query_params = (
                response_dict if response_type == ResponseType.TYPE_CODE else {}
            )
            fragment = response_dict if response_type == ResponseType.TYPE_TOKEN else {}

            location = build_uri(request.query.redirect_uri, query_params, fragment)
            headers = CaseInsensitiveDict({"location": location})
        except OAuth2Exception as exc:
            status_code = exc.status_code
            headers = exc.headers
            content = ErrorResponse(error=exc.error, description=exc.description)

        return Response(content=content, headers=headers, status_code=status_code)
