from .db import DBBase
from .exceptions import InsecureTransportError, MethodNotAllowedError
from .requests import Request
from .types import RequestMethod
from .utils import is_secure_transport


class BaseRequestValidator:
    allowed_methods = (
        RequestMethod.GET,
        RequestMethod.POST,
    )

    def __init__(self, db: DBBase):
        self.db = db

    async def validate_request(self, request: Request):
        if not is_secure_transport(request.url):
            raise InsecureTransportError(request=request)

        if request.method not in self.allowed_methods:
            raise MethodNotAllowedError(request=request)
