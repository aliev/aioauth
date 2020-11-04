from typing import Dict, Optional, Type, Union

from ..grant_type import GrantTypeBase
from ..response_type import ResponseTypeBase
from ..types import EndpointType, GrantType, ResponseType
from .database import BaseDB


class BaseEndpoint:
    response_type: Dict[Optional[ResponseType], Type[ResponseTypeBase]] = {}
    grant_type: Dict[Optional[GrantType], Type[GrantTypeBase]] = {}
    available: bool = True

    def __init__(
        self, db: BaseDB, available: Optional[bool] = None,
    ):
        self.db = db

        if available is not None:
            self.available = available

    def register(
        self,
        endpoint_type: EndpointType,
        endpoint: Union[ResponseType, GrantType],
        endpoint_cls: Union[Type[ResponseTypeBase], Type[GrantTypeBase]],
    ):
        endpoint_dict = getattr(self, endpoint_type)
        endpoint_dict[endpoint] = endpoint_cls

    def unregister(
        self, endpoint_type: EndpointType, endpoint: Union[ResponseType, GrantType]
    ):
        endpoint_dict = getattr(self, endpoint_type)
        del endpoint_dict[endpoint]
