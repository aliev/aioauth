from http import HTTPStatus
from typing import Type
from urllib.parse import quote, urlencode

from async_oauth2_provider.constances import default_headers
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.exceptions import OAuth2Exception
from async_oauth2_provider.grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    GrantTypeBase,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from async_oauth2_provider.requests import Request
from async_oauth2_provider.response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeBase,
    ResponseTypeToken,
)
from async_oauth2_provider.responses import ErrorResponse, Response
from async_oauth2_provider.types import GrantType, ResponseType


class OAuth2Endpoint:
    response_types = {
        ResponseType.TYPE_CODE: ResponseTypeAuthorizationCode,
        ResponseType.TYPE_TOKEN: ResponseTypeToken,
        None: ResponseTypeBase,  # Default response type
    }
    grant_types = {
        GrantType.TYPE_AUTHORIZATION_CODE: AuthorizationCodeGrantType,
        GrantType.TYPE_PASSWORD: PasswordGrantType,
        GrantType.TYPE_CLIENT_CREDENTIALS: ClientCredentialsGrantType,
        GrantType.TYPE_REFRESH_TOKEN: RefreshTokenGrantType,
        None: GrantTypeBase,  # Default grant type
    }

    def __init__(
        self, db_class: Type[DBBase],
    ):
        self.db_class = db_class

    async def create_token_response(self, request: Request) -> Response:
        grant_type_cls = self.grant_types.get(request.post.grant_type)
        grant_type_handler = grant_type_cls(self.db_class)

        status_code = HTTPStatus.OK
        headers = default_headers
        body = None

        try:
            body = await grant_type_handler.create_token_response(request)
        except OAuth2Exception as exc:
            status_code = exc.status_code
            headers = exc.headers
            body = ErrorResponse(
                error=exc.error, error_description=exc.error_description
            )

        return Response(body=body, status_code=status_code, headers=headers)

    async def create_authorization_response(self, request: Request) -> Response:
        response_type_cls = self.response_types.get(request.query.response_type)
        response_type_handler = response_type_cls(self.db_class)

        status_code = HTTPStatus.OK
        headers = default_headers
        body = None

        try:
            response = await response_type_handler.create_authorization_response(
                request
            )
            if response is not None:
                query_string = urlencode(response.dict(), quote_via=quote)
                fragment = (
                    "#"
                    if request.query.response_type == ResponseType.TYPE_CODE
                    else "?"
                )
                redirect_uri = f"{request.query.redirect_uri}{fragment}{query_string}"
                status_code = HTTPStatus.SEE_OTHER
                headers = {"location": redirect_uri}
            else:
                status_code = HTTPStatus.OK
        except OAuth2Exception as exc:
            status_code = exc.status_code
            headers = exc.headers
            body = ErrorResponse(
                error=exc.error, error_description=exc.error_description
            )

        return Response(body=body, headers=headers, status_code=status_code)
