from dataclasses import asdict
from http import HTTPStatus
from typing import Dict, Optional, Type, Union

from .constances import default_headers
from .db import DBBase
from .grant_type import GrantTypeBase
from .requests import Request
from .response_type import ResponseTypeBase
from .responses import (
    Response,
    TokenActiveIntrospectionResponse,
    TokenInactiveIntrospectionResponse,
)
from .structures import CaseInsensitiveDict
from .types import EndpointType, GrantType, ResponseType
from .utils import build_uri, catch_errors_and_unavailability, decode_basic_auth


class OAuth2Endpoint:
    response_type: Dict[Optional[ResponseType], Type[ResponseTypeBase]] = {}
    grant_type: Dict[Optional[GrantType], Type[GrantTypeBase]] = {}
    catch_errors: bool = False
    available: bool = True

    def __init__(
        self, db: DBBase, available: Optional[bool] = None,
    ):
        self.db = db

        if available is not None:
            self.available = available

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

    @catch_errors_and_unavailability
    async def create_token_introspection_response(self, request: Request) -> Response:
        client_id, _ = decode_basic_auth(request)

        token = await self.db.get_token(
            request=request, client_id=client_id, token=request.post.token
        )

        token_response = TokenInactiveIntrospectionResponse()
        if token:
            token_response = TokenActiveIntrospectionResponse(
                scope=token.scope, client_id=token.client_id, exp=token.expires_in
            )

        return Response(
            content=token_response, status_code=HTTPStatus.OK, headers=default_headers
        )

    @catch_errors_and_unavailability
    async def create_token_response(self, request: Request) -> Response:
        grant_type_cls = self.grant_type.get(request.post.grant_type, GrantTypeBase)
        grant_type_handler = grant_type_cls(self.db)
        token_response = await grant_type_handler.create_token_response(request)
        return Response(
            content=token_response, status_code=HTTPStatus.OK, headers=default_headers
        )

    @catch_errors_and_unavailability
    async def create_authorization_code_response(self, request: Request) -> Response:
        response_type_cls = self.response_type.get(
            request.query.response_type, ResponseTypeBase
        )
        response_type_handler = response_type_cls(self.db)
        authorization_code_response = await response_type_handler.create_authorization_code_response(
            request
        )
        response_type = request.query.response_type
        response_dict = {
            **asdict(authorization_code_response),
            "state": request.query.state,
        }
        query_params = response_dict if response_type == ResponseType.TYPE_CODE else {}
        fragment = response_dict if response_type == ResponseType.TYPE_TOKEN else {}

        location = build_uri(request.query.redirect_uri, query_params, fragment)

        return Response(
            status_code=HTTPStatus.FOUND,
            headers=CaseInsensitiveDict({"location": location}),
        )
