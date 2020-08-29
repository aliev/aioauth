from http import HTTPStatus
from typing import Dict, Optional, Type
from async_oauth2_provider.response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeBase,
    ResponseTypeToken,
)
from async_oauth2_provider.constances import default_headers
from async_oauth2_provider.types import GrantType, RequestMethod, ResponseType
from async_oauth2_provider.exceptions import OAuth2Exception

from async_oauth2_provider.responses import ErrorResponse, Response, TokenResponse

from async_oauth2_provider.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    GrantTypeBase,
    PasswordGrantType,
    RefreshTokenGrantType,
)

from async_oauth2_provider.requests import Request
from async_oauth2_provider.request_validators import BaseRequestValidator


class OAuth2Endpoint:
    response_types = {
        ResponseType.TYPE_CODE: ResponseTypeAuthorizationCode,
        ResponseType.TYPE_TOKEN: ResponseTypeToken,
        None: ResponseTypeAuthorizationCode,  # Default response type
    }
    grant_types = {
        GrantType.TYPE_AUTHORIZATION_CODE: AuthorizationCodeGrantType,
        GrantType.TYPE_PASSWORD: PasswordGrantType,
        GrantType.TYPE_CLIENT_CREDENTIALS: ClientCredentialsGrantType,
        GrantType.TYPE_REFRESH_TOKEN: RefreshTokenGrantType,
        None: AuthorizationCodeGrantType,  # Default grant type
    }

    def __init__(
        self, request_validator_cls: Type[BaseRequestValidator],
    ):
        self.request_validator_cls = request_validator_cls

    async def create_token_response(self, request: Request):
        grant_type_cls = self.grant_types.get(request.post.grant_type)
        grant_type_handler = grant_type_cls(self.request_validator_cls)

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
        response_type_cls = self.response_types.get(request.query.response_type)
        response_type_handler = response_type_cls(self.request_validator_cls)

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

            if request.method == RequestMethod.POST:
                status_code = HTTPStatus.SEE_OTHER
                headers = {"location": redirect_url}
            else:
                status_code = HTTPStatus.OK
                headers = {}

        return Response(status_code=status_code, headers=headers, body=body)
