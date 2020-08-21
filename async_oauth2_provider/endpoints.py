from http import HTTPStatus
from typing import Dict, Optional, Type
from async_oauth2_provider.response_type import ResponseTypeBase
from async_oauth2_provider.constances import default_headers
from async_oauth2_provider.types import GrantType, RequestMethod, ResponseType
from async_oauth2_provider.exceptions import OAuth2Exception

from async_oauth2_provider.responses import ErrorResponse, Response, TokenResponse

from async_oauth2_provider.grant_type import GrantTypeBase

from async_oauth2_provider.requests import Request
from async_oauth2_provider.request_validators import BaseRequestValidator


class OAuth2Endpoint:
    default_grant_type: Type[GrantTypeBase] = GrantTypeBase
    default_response_type: Type[ResponseTypeBase] = ResponseTypeBase

    def __init__(
        self,
        grant_types: Dict[Optional[GrantType], Type[GrantTypeBase]],
        response_types: Dict[Optional[ResponseType], Type[ResponseTypeBase]],
        request_validator_class: Type[BaseRequestValidator],
    ):
        self.grant_types = grant_types
        self.response_types = response_types
        self.request_validator_class = request_validator_class

    async def create_token_response(self, request: Request):
        grant_type_name = request.post.grant_type
        grant_type_cls = self.grant_types.get(grant_type_name, self.default_grant_type)
        grant_type_handler = grant_type_cls(self.request_validator_class)

        try:
            token = await grant_type_handler.create_token(request)
        except OAuth2Exception as exc:
            headers = exc.headers
            status_code = exc.status_code
            error = exc.error
            error_description = exc.error_description

            body = ErrorResponse(error=error, error_description=error_description)
        else:
            headers = default_headers
            status_code = HTTPStatus.OK
            body = TokenResponse.from_orm(token)

        return Response(headers=headers, body=body, status_code=status_code)

    async def create_authorization_response(self, request: Request):
        response_type_name = request.query.response_type
        response_type_cls = self.response_types.get(
            response_type_name, self.default_response_type
        )
        response_type_handler = response_type_cls(self.request_validator_class)

        try:
            redirect_url = await response_type_handler.get_redirect_uri(request)
        except OAuth2Exception as exc:
            headers = exc.headers
            status_code = exc.status_code
            error = exc.error
            error_description = exc.error_description
            body = ErrorResponse(error=error, error_description=error_description)
        else:
            body = None
            status_code = HTTPStatus.SEE_OTHER
            headers = {"location": redirect_url}

        if request.method == RequestMethod.POST:
            return Response(status_code=status_code, headers=headers, body=body)
        if request.method == RequestMethod.GET:
            return Response(status_code=HTTPStatus.OK)
