from http import HTTPStatus
from typing import Dict, List, Optional, Union

from .storage import BaseStorage
from .constances import default_headers
from .errors import (
    InsecureTransportError,
    InvalidRequestError,
    MethodNotAllowedError,
    TemporarilyUnavailableError,
    UnsupportedGrantTypeError,
    UnsupportedResponseTypeError,
)
from .grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from .requests import Request
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
from .structures import CaseInsensitiveDict
from .types import GrantType, RequestMethod, ResponseMode, ResponseType
from .utils import (
    build_uri,
    catch_errors_and_unavailability,
    decode_auth_headers,
    enforce_list,
    is_secure_transport,
)


class AuthorizationServer:
    response_types = {
        ResponseType.TYPE_TOKEN: ResponseTypeToken,
        ResponseType.TYPE_CODE: ResponseTypeAuthorizationCode,
        ResponseType.TYPE_NONE: ResponseTypeNone,
        ResponseType.TYPE_ID_TOKEN: ResponseTypeIdToken,
    }
    grant_types = {
        GrantType.TYPE_AUTHORIZATION_CODE: AuthorizationCodeGrantType,
        GrantType.TYPE_CLIENT_CREDENTIALS: ClientCredentialsGrantType,
        GrantType.TYPE_PASSWORD: PasswordGrantType,
        GrantType.TYPE_REFRESH_TOKEN: RefreshTokenGrantType,
    }

    def __init__(
        self,
        storage: BaseStorage,
        response_types: Optional[Dict] = None,
        grant_types: Optional[Dict] = None,
    ):
        self.storage = storage

        if response_types is not None:
            self.response_types = response_types

        if grant_types is not None:
            self.grant_types = grant_types

    def validate_request(self, request: Request, allowed_methods: List[RequestMethod]):
        if not request.settings.AVAILABLE:
            raise TemporarilyUnavailableError(request=request)

        if not is_secure_transport(request):
            raise InsecureTransportError(request=request)

        if request.method not in allowed_methods:
            headers = CaseInsensitiveDict(
                {**default_headers, "allow": ", ".join(allowed_methods)}
            )
            raise MethodNotAllowedError(request=request, headers=headers)

    @catch_errors_and_unavailability
    async def create_token_introspection_response(self, request: Request) -> Response:
        """Endpoint returns information about a token.

        See Section 2.1: https://tools.ietf.org/html/rfc7662#section-2.1
        """
        self.validate_request(request, [RequestMethod.POST])
        client_id, _ = decode_auth_headers(request)

        token = await self.storage.get_token(
            request=request, client_id=client_id, access_token=request.post.token
        )

        token_response: Union[
            TokenInactiveIntrospectionResponse, TokenActiveIntrospectionResponse
        ]

        token_response = TokenInactiveIntrospectionResponse()

        if token and not token.is_expired and not token.revoked:
            token_response = TokenActiveIntrospectionResponse(
                scope=token.scope, client_id=token.client_id, exp=token.expires_in
            )

        content = token_response._asdict()

        return Response(
            content=content, status_code=HTTPStatus.OK, headers=default_headers
        )

    @catch_errors_and_unavailability
    async def create_token_response(self, request: Request) -> Response:
        """Endpoint to obtain an access and/or ID token by presenting an authorization grant or refresh token.

        Validate token request and create token response.

        See Section 4.1.3: https://tools.ietf.org/html/rfc6749#section-4.1.3
        """
        self.validate_request(request, [RequestMethod.POST])

        if not request.post.grant_type:
            # grant_type request value is empty
            raise InvalidRequestError(
                request=request, description="Request is missing grant type."
            )

        GrantTypeClass = self.grant_types.get(request.post.grant_type)

        if GrantTypeClass is None:
            # Requested GrantType was not found in the list of the grant_types.
            raise UnsupportedGrantTypeError(request=request)

        grant_type = GrantTypeClass(storage=self.storage)

        response = await grant_type.create_token_response(request)
        content = response._asdict()

        return Response(
            content=content, status_code=HTTPStatus.OK, headers=default_headers
        )

    @catch_errors_and_unavailability
    async def create_authorization_response(self, request: Request) -> Response:
        """Endpoint to interact with the resource owner and obtain an authorization grant.

        Validate authorization request and create authorization response.

        See Section 4.1.1: https://tools.ietf.org/html/rfc6749#section-4.1.1
        """
        self.validate_request(request, [RequestMethod.GET])

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

        if not response_type_list:
            raise InvalidRequestError(
                request=request, description="Missing response_type parameter."
            )

        if request.query.state:
            responses["state"] = request.query.state

        for response_type in response_type_list:
            ResponseTypeClass = self.response_types.get(response_type)
            if ResponseTypeClass:
                response_type_classes.add(ResponseTypeClass)

        if not response_type_classes:
            raise UnsupportedResponseTypeError(request=request)

        for ResponseTypeClass in response_type_classes:
            response_type = ResponseTypeClass(storage=self.storage)
            response = await response_type.create_authorization_response(request)
            responses.update(response._asdict())

        # See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
        if ResponseType.TYPE_CODE in response_type_list:
            """
            The TYPE_CODE has lowest priority.
            The response will be placed in query.
            """
            query = responses

        if ResponseType.TYPE_TOKEN in response_type_list:
            """
            The TYPE_TOKEN has middle priority.
            The response will be placed in fragment.
            """
            query = {}
            fragment = responses

        if ResponseType.TYPE_ID_TOKEN in response_type_list:
            """
            The TYPE_ID_TOKEN has highest priority.
            The response can be placed in query, fragment or content
            depending on the response_mode.
            """
            if request.query.response_mode == ResponseMode.MODE_FORM_POST:
                query = {}
                fragment = {}
                content = responses
            elif request.query.response_mode == ResponseMode.MODE_FRAGMENT:
                query = {}
                content = {}
                fragment = responses
            elif request.query.response_mode == ResponseMode.MODE_QUERY:
                content = {}
                fragment = {}
                query = responses

        location = build_uri(request.query.redirect_uri, query, fragment)

        return Response(
            status_code=HTTPStatus.FOUND,
            headers=CaseInsensitiveDict({"location": location}),
            content=content,
        )
