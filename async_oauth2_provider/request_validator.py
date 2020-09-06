from async_oauth2_provider.exceptions import (
    InsecureTransportError,
    MethodNotAllowedError,
)
from async_oauth2_provider.requests import Request
from async_oauth2_provider.types import RequestMethod
from async_oauth2_provider.utils import is_secure_transport
from db import DBBase


class BaseRequestValidator:
    allowed_methods = (
        RequestMethod.GET,
        RequestMethod.POST,
    )

    def __init__(self, db: DBBase):
        self.db = db

    async def validate_request(self, request: Request):
        if not is_secure_transport(request.url):
            raise InsecureTransportError()

        if request.method not in self.allowed_methods:
            raise MethodNotAllowedError()
