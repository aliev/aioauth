from typing import Type
from async_oauth2_provider.exceptions import OAuth2Exception

from async_oauth2_provider.responses import ErrorResponse, Response, TokenResponse

from async_oauth2_provider.grant_type import GrantTypeBase

from async_oauth2_provider.requests import Request
from async_oauth2_provider.request_validators import BaseRequestValidator


class TokenEndpoint:
    default_grant_type: Type[GrantTypeBase]
    grant_types: dict
    request_validator_class: Type[BaseRequestValidator]

    def __init__(
        self,
        grant_types: dict,
        request_validator_class: Type[BaseRequestValidator],
        default_grant_type: Type[GrantTypeBase] = GrantTypeBase,
    ):
        self.default_grant_type = default_grant_type
        self.grant_types = grant_types
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

            return Response(headers=headers, status_code=status_code, body=body)

        token_response = TokenResponse.from_orm(token)

        return Response(body=token_response)
