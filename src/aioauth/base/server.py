from typing import Dict, Optional, Type, Union

from ..grant_type import (
    AuthorizationCodeGrantType,
    ClientCredentialsGrantType,
    GrantTypeBase,
    PasswordGrantType,
    RefreshTokenGrantType,
)
from ..response_type import (
    ResponseTypeAuthorizationCode,
    ResponseTypeBase,
    ResponseTypeToken,
)
from ..types import EndpointType, GrantType, ResponseType
from .database import BaseDB


class BaseAuthorizationServer:
    response_type: Dict[Optional[ResponseType], Type[ResponseTypeBase]] = {
        ResponseType.TYPE_TOKEN: ResponseTypeToken,
        ResponseType.TYPE_CODE: ResponseTypeAuthorizationCode,
    }
    grant_type: Dict[Optional[GrantType], Type[GrantTypeBase]] = {
        GrantType.TYPE_AUTHORIZATION_CODE: AuthorizationCodeGrantType,
        GrantType.TYPE_CLIENT_CREDENTIALS: ClientCredentialsGrantType,
        GrantType.TYPE_PASSWORD: PasswordGrantType,
        GrantType.TYPE_REFRESH_TOKEN: RefreshTokenGrantType,
    }

    def __init__(self, db: BaseDB):
        self.db = db

    def register(
        self,
        endpoint_type: EndpointType,
        server: Union[ResponseType, GrantType],
        endpoint_cls: Union[Type[ResponseTypeBase], Type[GrantTypeBase]],
    ):
        endpoint_dict = getattr(self, endpoint_type)
        endpoint_dict[server] = endpoint_cls

    def unregister(
        self, endpoint_type: EndpointType, server: Union[ResponseType, GrantType]
    ):
        endpoint_dict = getattr(self, endpoint_type)
        del endpoint_dict[server]
