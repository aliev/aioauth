from functools import cached_property
from typing import Any, Dict, List, Optional

from aioauth.config import Settings
from aioauth.models import AuthorizationCode, Client, Token
from aioauth.types import GrantType, ResponseType
from aioauth.requests import Request
from aioauth.server import AuthorizationServer

from tests.classes import Storage


class AuthorizationContext:
    def __init__(
        self,
        clients: Optional[List[Client]] = None,
        grant_types: Optional[Dict[GrantType, Any]] = None,
        initial_authorization_codes: Optional[List[AuthorizationCode]] = None,
        initial_tokens: Optional[List[Token]] = None,
        response_types: Optional[Dict[ResponseType, Any]] = None,
        settings: Optional[Settings] = None,
        users: Dict[str, str] = None,
    ):
        self.initial_authorization_codes = initial_authorization_codes or []
        self.initial_tokens = initial_tokens or []

        self.clients: List[Client] = clients or []
        self.grant_types = grant_types or {}
        self.response_types = response_types or {}
        self.settings = settings or Settings(INSECURE_TRANSPORT=True)
        self.users = users or {}

    @cached_property
    def server(self) -> AuthorizationServer[Request, Storage]:
        return AuthorizationServer(
            grant_types=self.grant_types,
            response_types=self.response_types,
            storage=self.storage,
        )

    @cached_property
    def storage(self) -> Storage:
        return Storage(
            authorization_codes=self.initial_authorization_codes,
            clients=self.clients,
            tokens=self.initial_tokens,
            users=self.users,
        )
