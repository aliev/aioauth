"""
.. code-block:: python

    from aioauth import server

Memory object and interface used to initialize an OAuth2.0 server
instance.

Warning:
    Note that :py:class:`aioauth.server.AuthorizationServer` is not
    depedent on any server framework, nor serves at any specific
    endpoint. Instead, it is used to create an interface that can be
    used in conjunction with a server framework like ``FastAPI`` or
    ``aiohttp`` to create a fully functional OAuth 2.0 server.

    Check out the *Examples* portion of the documentation to understand
    how it can be leveraged in your own project.

----
"""

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
    """Interface for initializing an OAuth 2.0 server."""

    @catch_errors_and_unavailability
    async def create_token_response(self, request: Request) -> Response:
        """Endpoint to obtain an access and/or ID token by presenting an
        authorization grant or refresh token.

        Validates a token request and creates a token response.

        For more information see
        `RFC6749 section 4.1.3 <https://tools.ietf.org/html/rfc6749#section-4.1.3>`_.

        Note:
            The API endpoint that leverages this function is usually
            ``/token``.

        Example:
            Below is an example utilizing FastAPI as the server framework.

            .. code-block:: python

                @app.post("/token")
                async def token(request: fastapi.Request) -> fastapi.Response:

                    # Converts a fastapi.Request to an aioauth.Request.
                    oauth2_request: aioauth.Request = await to_oauth2_request(request)

                    # Creates the response via this function call.
                    oauth2_response: aioauth.Response = await server.create_token_response(oauth2_request)

                    # Converts an aioauth.Response to a fastapi.Response.
                    response: fastapi.Response = await to_fastapi_response(oauth2_response)

                    return response

        Args:
            request: An ``aioauth`` request object.

        Returns:
            response: An ``aioauth`` response object.

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
        """
        Endpoint to interact with the resource owner and obtain an
        authorization grant.

        Validate authorization request and create authorization response.

        For more information see
        `RFC6749 section 4.1.1 <https://tools.ietf.org/html/rfc6749#section-4.1.1>`_.

        Note:
            The API endpoint that leverages this function is usually
            ``/authorize``.

        Example:
            Below is an example utilizing FastAPI as the server framework.

            .. code-block:: python

                @app.post("/authorize")
                async def authorize(request: fastapi.Request) -> fastapi.Response:

                    # Converts a fastapi.Request to an aioauth.Request.
                    oauth2_request: aioauth.Request = await to_oauth2_request(request)

                    # Creates the response via this function call.
                    oauth2_response: aioauth.Response = await server.create_authorization_response(oauth2_request)

                    # Converts an aioauth.Response to a fastapi.Response.
                    response: fastapi.Response = await to_fastapi_response(oauth2_response)

                    return response

        Args:
            request: An ``aioauth`` request object.

        Returns:
            response: An ``aioauth`` response object.
        """
        ResponseTypeClass: Union[
            Type[ResponseTypeToken],
            Type[ResponseTypeAuthorizationCode],
            Type[ResponseTypeBase],
        ] = self.response_type.get(request.query.response_type, ResponseTypeBase)
        response_type = ResponseTypeClass(db=self.db)

        response = await response_type.create_authorization_response(request)

        response_dict = {
            **response.__dict__,
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

    @catch_errors_and_unavailability
    async def create_token_introspection_response(self, request: Request) -> Response:
        """
        Returns a response object with introspection of the passed token.

        For more information see
        `RFC7662 section 2.1 <https://tools.ietf.org/html/rfc7662#section-2.1>`_.

        Note:
            The API endpoint that leverages this function is usually
            ``/introspect``.

        Example:
            Below is an example utilizing FastAPI as the server framework.

            .. code-block:: python

                @app.get("/introspect")
                async def introspect(request: fastapi.Request) -> fastapi.Response:

                    # Converts a fastapi.Request to an aioauth.Request.
                    oauth2_request: aioauth.Request = await to_oauth2_request(request)

                    # Creates the response via this function call.
                    oauth2_response: aioauth.Response = await server.create_token_introspection_response(oauth2_request)

                    # Converts an aioauth.Response to a fastapi.Response.
                    response: fastapi.Response = await to_fastapi_response(oauth2_response)

                    return response

        Args:
            request: An ``aioauth`` request object.

        Returns:
            response: An ``aioauth`` response object.
        """
        client_id, _ = decode_auth_headers(request)

        token = await self.db.get_token(
            request=request, client_id=client_id, access_token=request.post.token,
        )

        token_response = TokenInactiveIntrospectionResponse()

        if token and not token.is_expired(request) and not token.revoked:
            token_response = TokenActiveIntrospectionResponse(
                scope=token.scope, client_id=token.client_id, exp=token.expires_in,
            )

        return Response(
            content=token_response, status_code=HTTPStatus.OK, headers=default_headers,
        )
