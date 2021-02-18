from http import HTTPStatus
from typing import Type, Union

from .base.server import BaseAuthorizationServer
from .constances import default_headers
from .grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    GrantTypeBase,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from .requests import Request
from .response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeBase,
    ResponseTypeToken,
)
from .responses import (
    Response,
    TokenActiveIntrospectionResponse,
    TokenInactiveIntrospectionResponse,
)
from .structures import CaseInsensitiveDict
from .types import ResponseType
from .utils import build_uri, catch_errors_and_unavailability, decode_auth_headers


class AuthorizationServer(BaseAuthorizationServer):
    @catch_errors_and_unavailability
    async def create_token_introspection_response(self, request: Request) -> Response:
        """Endpoint returns information about a token.

        See Section 2.1: https://tools.ietf.org/html/rfc7662#section-2.1
        """
        client_id, _ = decode_auth_headers(request)

        token = await self.db.get_token(
            request=request, client_id=client_id, access_token=request.post.token
        )

        token_response = TokenInactiveIntrospectionResponse()

        if token and not token.is_expired(request) and not token.revoked:
            token_response = TokenActiveIntrospectionResponse(
                scope=token.scope, client_id=token.client_id, exp=token.expires_in
            )

        return Response(
            content=token_response, status_code=HTTPStatus.OK, headers=default_headers
        )

    @catch_errors_and_unavailability
    async def create_token_response(self, request: Request) -> Response:
        """Endpoint to obtain an access and/or ID token by presenting an authorization grant or refresh token.

        Validate token request and create token response.

        See Section 4.1.3: https://tools.ietf.org/html/rfc6749#section-4.1.3
        """
        GrantTypeClass: Union[
            Type[AuthorizationCodeGrantType],
            Type[ClientCredentialsGrantType],
            Type[PasswordGrantType],
            Type[RefreshTokenGrantType],
            Type[GrantTypeBase],
        ] = self.grant_type.get(request.post.grant_type, GrantTypeBase)
        grant_type = GrantTypeClass(db=self.db)

        response = await grant_type.create_token_response(request)

        return Response(
            content=response, status_code=HTTPStatus.OK, headers=default_headers
        )

    @catch_errors_and_unavailability
    async def create_authorization_response(self, request: Request) -> Response:
        """Endpoint to interact with the resource owner and obtain an authorization grant.

        Validate authorization request and create authorization response.

        See Section 4.1.1: https://tools.ietf.org/html/rfc6749#section-4.1.1
        """
        ResponseTypeClass: Union[
            Type[ResponseTypeToken],
            Type[ResponseTypeAuthorizationCode],
            Type[ResponseTypeBase],
        ] = self.response_type.get(request.query.response_type, ResponseTypeBase)
        response_type = ResponseTypeClass(db=self.db)

        response = await response_type.create_authorization_response(request)

        response_dict = {
            **response._asdict(),
            "state": request.query.state,
        }
        query_params = (
            response_dict
            if request.query.response_type == ResponseType.TYPE_CODE
            else {}
        )
        fragment = (
            response_dict
            if request.query.response_type == ResponseType.TYPE_TOKEN
            else {}
        )

        location = build_uri(request.query.redirect_uri, query_params, fragment)

        return Response(
            status_code=HTTPStatus.FOUND,
            headers=CaseInsensitiveDict({"location": location}),
        )
