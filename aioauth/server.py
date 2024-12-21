"""
.. code-block:: python

    from aioauth import server

Memory object and interface used to initialize an OAuth2.0 server instance.

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

from dataclasses import asdict
from http import HTTPStatus
from typing import Any, Dict, Generic, List, Optional, Tuple, Type, Union, get_args

from .requests import Request
from .types import UserType
from .storage import BaseStorage


from .collections import HTTPHeaderDict
from .constances import default_headers
from .errors import (
    InsecureTransportError,
    InvalidClientError,
    InvalidRedirectURIError,
    InvalidRequestError,
    MethodNotAllowedError,
    TemporarilyUnavailableError,
    UnsupportedGrantTypeError,
    UnsupportedResponseTypeError,
    UnsupportedTokenTypeError,
)
from .grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    GrantTypeBase,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from .response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeIdToken,
    ResponseTypeNone,
    ResponseTypeToken,
)
from .responses import (
    Response,
    TokenActiveIntrospectionResponse,
    TokenInactiveIntrospectionResponse,
)
from .types import (
    GrantType,
    RequestMethod,
    ResponseType,
    TokenType,
)
from .utils import (
    build_uri,
    catch_errors_and_unavailability,
    decode_auth_headers,
    enforce_list,
)


class AuthorizationServer(Generic[UserType]):
    """Interface for initializing an OAuth 2.0 server."""

    response_types: Dict[ResponseType, Any] = {
        "token": ResponseTypeToken[UserType],
        "code": ResponseTypeAuthorizationCode[UserType],
        "none": ResponseTypeNone[UserType],
        "id_token": ResponseTypeIdToken[UserType],
    }
    grant_types: Dict[GrantType, Any] = {
        "authorization_code": AuthorizationCodeGrantType[UserType],
        "client_credentials": ClientCredentialsGrantType[UserType],
        "password": PasswordGrantType[UserType],
        "refresh_token": RefreshTokenGrantType[UserType],
    }

    def __init__(
        self,
        storage: BaseStorage[UserType],
        response_types: Optional[Dict] = None,
        grant_types: Optional[Dict] = None,
    ):
        self.storage = storage

        if response_types is not None:
            self.response_types = response_types

        if grant_types is not None:
            self.grant_types = grant_types

    def is_secure_transport(self, request: Request[UserType]) -> bool:
        """
        Verifies the request was sent via a protected SSL tunnel.

        Note:
            This method simply checks if the request URL contains
            ``https://`` at the start of it. It does **not** ensure
            if the SSL certificate is valid.
        Args:
            request: :py:class:`aioauth.requests.Request` object.
        Returns:
            Flag representing whether or not the transport is secure.
        """
        if request.settings.INSECURE_TRANSPORT:
            return True
        return request.url.lower().startswith("https://")

    def validate_request(
        self, request: Request[UserType], allowed_methods: List[RequestMethod]
    ):
        if not request.settings.AVAILABLE:
            raise TemporarilyUnavailableError[UserType](request=request)

        if not self.is_secure_transport(request):
            raise InsecureTransportError[UserType](request=request)

        if request.method not in allowed_methods:
            headers = HTTPHeaderDict(
                {**default_headers, "allow": ", ".join(allowed_methods)}
            )
            raise MethodNotAllowedError[UserType](request=request, headers=headers)

    @catch_errors_and_unavailability()
    async def create_token_introspection_response(
        self, request: Request[UserType]
    ) -> Response:
        """
        Returns a response object with introspection of the passed token.
        For more information see `RFC7662 section 2.1 <https://tools.ietf.org/html/rfc7662#section-2.1>`_.

        Note:
            The API endpoint that leverages this function is usually
            ``/introspect``.

        Example:
            Below is an example utilizing FastAPI as the server framework.
        .. code-block:: python

            from aioauth_fastapi.utils import to_oauth2_request, to_fastapi_response

            @app.get("/token/introspect")
            async def introspect(request: fastapi.Request) -> fastapi.Response:
                # Converts a fastapi.Request to an aioauth.Request.
                oauth2_request: aioauth.Request = await to_oauth2_request(request)
                # Creates the response via this function call.
                oauth2_response: aioauth.Response = await server.create_token_introspection_response(oauth2_request)
                # Converts an aioauth.Response to a fastapi.Response.
                response: fastapi.Response = await to_fastapi_response(oauth2_response)
                return response

        Args:
            request: An :py:class:`aioauth.requests.Request` object.

        Returns:
            response: An :py:class:`aioauth.responses.Response` object.
        """
        self.validate_request(request, ["POST"])
        client_id, client_secret = self.get_client_credentials(
            request, secret_required=True
        )

        client = await self.storage.get_client(
            request=request, client_id=client_id, client_secret=client_secret
        )

        if not client:
            raise InvalidClientError[UserType](request)

        token_types: Tuple[TokenType, ...] = get_args(TokenType)
        token_type: TokenType = "refresh_token"

        access_token = None
        refresh_token = request.post.token

        if request.post.token_type_hint in token_types:
            token_type = request.post.token_type_hint

        if token_type == "access_token":  # nosec
            access_token = request.post.token
            refresh_token = None

        token = await self.storage.get_token(
            request=request,
            client_id=client_id,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type,
        )

        token_response: Union[
            TokenInactiveIntrospectionResponse, TokenActiveIntrospectionResponse
        ]

        if token and not token.is_expired and not token.revoked:
            token_response = TokenActiveIntrospectionResponse(
                scope=token.scope,
                client_id=token.client_id,
                expires_in=token.expires_in,
                token_type=token.token_type,
            )
        else:
            token_response = TokenInactiveIntrospectionResponse()

        content = asdict(token_response)

        return Response(
            content=content, status_code=HTTPStatus.OK, headers=default_headers
        )

    def get_client_credentials(
        self, request: Request[UserType], secret_required: bool
    ) -> Tuple[str, str]:
        client_id = request.post.client_id
        client_secret = request.post.client_secret

        if client_id is None or client_secret is None:
            authorization = request.headers.get("Authorization", "")

            # Get client credentials from the Authorization header.
            try:
                client_id, client_secret = decode_auth_headers(authorization)
            except ValueError as exc:
                if client_id is None or secret_required:
                    # Either we didn't find a client ID at all, or we found
                    # a client ID but no secret and a secret is required.
                    raise InvalidClientError[UserType](
                        description="Invalid client_id parameter value.",
                        request=request,
                    ) from exc

        # client_secret must not be None. When client_secret is None,
        # storage.get_client will not run standard checks on the client_secret
        if client_secret is None:
            client_secret = ""  # nosec

        return client_id, client_secret

    @catch_errors_and_unavailability()
    async def create_token_response(self, request: Request[UserType]) -> Response:
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

            from aioauth_fastapi.utils import to_oauth2_request, to_fastapi_response

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
            request: An :py:class:`aioauth.requests.Request` object.

        Returns:
            response: An :py:class:`aioauth.responses.Response` object.
        """
        self.validate_request(request, ["POST"])

        client_secret: Optional[str] = None

        # client_secret is required for the client_credentials grant type
        # https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
        #
        # for other grant types, client_secret is required if the client has one:
        # If the client type is confidential or the client was issued client credentials
        # (or assigned other authentication requirements), the client MUST authenticate
        # with the authorization server as described in Section 3.2.1.
        # https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
        secret_required = request.post.grant_type == "client_credentials"

        client_id, client_secret = self.get_client_credentials(
            request, secret_required=secret_required
        )

        if not request.post.grant_type:
            # grant_type request value is empty
            raise InvalidRequestError[UserType](
                request=request, description="Request is missing grant type."
            )

        GrantTypeClass: Type[
            Union[
                GrantTypeBase[UserType],
                AuthorizationCodeGrantType[UserType],
                PasswordGrantType[UserType],
                RefreshTokenGrantType[UserType],
                ClientCredentialsGrantType[UserType],
            ]
        ]

        try:
            GrantTypeClass = self.grant_types[request.post.grant_type]
        except KeyError as exc:
            # grant_type request value is invalid
            raise UnsupportedGrantTypeError[UserType](request=request) from exc

        grant_type = GrantTypeClass(
            storage=self.storage, client_id=client_id, client_secret=client_secret
        )

        client = await grant_type.validate_request(request)

        response = await grant_type.create_token_response(request, client)
        content = asdict(response)

        return Response(
            content=content, status_code=HTTPStatus.OK, headers=default_headers
        )

    @catch_errors_and_unavailability(
        skip_redirect_on_exc=(
            MethodNotAllowedError,
            InvalidClientError,
            InvalidRedirectURIError,
        )
    )
    async def create_authorization_response(
        self, request: Request[UserType]
    ) -> Response:
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

            from aioauth.fastapi.utils import to_oauth2_request, to_fastapi_response

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
            request: An :py:class:`aioauth.requests.Request` object.

        Returns:
            response: An :py:class:`aioauth.responses.Response` object.
        """
        self.validate_request(request, ["GET", "POST"])

        response_type_list = enforce_list(request.query.response_type)
        response_type_classes = set()

        # Combined responses
        responses = {}

        # URI fragment
        fragment = {}

        # URI query params
        query = {}

        # Response content
        content = {}

        state = request.query.state

        if not response_type_list:
            raise InvalidRequestError[UserType](
                request=request,
                description="Missing response_type parameter.",
                state=state,
            )

        if state:
            responses["state"] = state

        for response_type in response_type_list:
            ResponseTypeClass = self.response_types.get(response_type)
            if ResponseTypeClass:
                response_type_classes.add(ResponseTypeClass)

        if not response_type_classes:
            raise UnsupportedResponseTypeError[UserType](request=request, state=state)

        for ResponseTypeClass in response_type_classes:
            response_type = ResponseTypeClass(storage=self.storage)
            client = await response_type.validate_request(request)
            response = await response_type.create_authorization_response(
                request, client
            )
            response_asdict = asdict(response)
            if (
                isinstance(response_type, ResponseTypeToken)
                and not request.settings.ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT
            ):
                # This is the implicit grant where the generation of refresh token has
                # been disabled in settings
                response_asdict.pop("refresh_token")
                response_asdict.pop("refresh_token_expires_in")
            responses.update(response_asdict)

        # See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
        if "code" in response_type_list:
            """
            The TYPE_CODE has lowest priority.
            The response will be placed in query.
            """
            query = responses

        if "token" in response_type_list:
            """
            The TYPE_TOKEN has middle priority.
            The response will be placed in fragment.
            """
            query = {}
            fragment = responses

        if "id_token" in response_type_list:
            """
            The TYPE_ID_TOKEN has highest priority.
            The response can be placed in query, fragment or content
            depending on the response_mode.
            """
            if request.query.response_mode == "form_post":
                query = {}
                fragment = {}
                content = responses
            elif request.query.response_mode == "fragment":
                query = {}
                content = {}
                fragment = responses
            elif request.query.response_mode == "query":
                content = {}
                fragment = {}
                query = responses

        location = build_uri(request.query.redirect_uri, query, fragment)

        return Response(
            status_code=HTTPStatus.FOUND,
            headers=HTTPHeaderDict({"location": location}),
            content=content,
        )

    @catch_errors_and_unavailability()
    async def revoke_token(self, request: Request[UserType]) -> Response:
        """Endpoint to revoke an access token or refresh token.
        For more information see
        `RFC7009 <https://tools.ietf.org/html/rfc7009>`_.

        Note:
            The API endpoint that leverages this function is usually
            ``/revoke``.
        Example:
            Below is an example utilizing FastAPI as the server framework.
        .. code-block:: python

            from aioauth_fastapi.utils import to_oauth2_request, to_fastapi_response

            @app.post("/revoke")
            async def revoke(request: fastapi.Request) -> fastapi.Response:
                # Converts a fastapi.Request to an aioauth.Request.
                oauth2_request: aioauth.Request = await to_oauth2_request(request)
                # Creates the response via this function call.
                oauth2_response: aioauth.Response = await server.revoke_token(oauth2_request)
                # Converts an aioauth.Response to a fastapi.Response.
                response: fastapi.Response = await to_fastapi_response(oauth2_response)
                return response

        Args:
            request: An :py:class:`aioauth.requests.Request` object.

        Returns:
            response: An :py:class:`aioauth.responses.Response` object.
        """
        self.validate_request(request, ["POST"])
        client_id, client_secret = self.get_client_credentials(
            request, secret_required=False
        )

        client = await self.storage.get_client(
            request=request, client_id=client_id, client_secret=client_secret
        )

        if not client:
            raise InvalidClientError[UserType](request)

        if not request.post.token:
            raise InvalidRequestError[UserType](
                request=request, description="Request is missing token."
            )

        if request.post.token_type_hint and request.post.token_type_hint not in {
            "refresh_token",
            "access_token",
        }:
            raise UnsupportedTokenTypeError[UserType](request=request)

        access_token = (
            request.post.token
            if request.post.token_type_hint != "refresh_token"  # nosec
            else None
        )
        refresh_token = (
            request.post.token
            if request.post.token_type_hint != "access_token"  # nosec
            else None
        )

        token = await self.storage.get_token(
            request=request,
            client_id=client_id,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=request.post.token_type_hint,
        )

        if token:
            await self.storage.revoke_token(
                request=request,
                client_id=client_id,
                access_token=access_token,
                refresh_token=refresh_token,
                token_type=request.post.token_type_hint,
            )

        return Response(status_code=HTTPStatus.NO_CONTENT)
