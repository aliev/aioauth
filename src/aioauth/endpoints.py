from http import HTTPStatus

from .base.endpoint import BaseEndpoint
from .constances import default_headers
from .grant_type import GrantTypeBase
from .requests import Request
from .response_type import ResponseTypeBase
from .responses import (
    Response,
    TokenActiveIntrospectionResponse,
    TokenInactiveIntrospectionResponse,
)
from .structures import CaseInsensitiveDict
from .types import ResponseType
from .utils import build_uri, catch_errors_and_unavailability, decode_auth_headers


class Endpoint(BaseEndpoint):
    @catch_errors_and_unavailability
    async def create_token_introspection_response(self, request: Request) -> Response:
        client_id, _ = decode_auth_headers(request)

        token = await self.db.get_token(
            request=request, client_id=client_id, token=request.post.token
        )

        token_response = TokenInactiveIntrospectionResponse()

        if token and not token.is_expired(request):
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
            **authorization_code_response._asdict(),
            "state": request.query.state,
        }
        query_params = response_dict if response_type == ResponseType.TYPE_CODE else {}
        fragment = response_dict if response_type == ResponseType.TYPE_TOKEN else {}

        location = build_uri(request.query.redirect_uri, query_params, fragment)

        return Response(
            status_code=HTTPStatus.FOUND,
            headers=CaseInsensitiveDict({"location": location}),
        )
