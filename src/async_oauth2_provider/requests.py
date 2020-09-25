from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .types import GrantType, RequestMethod, ResponseType


@dataclass
class Query:
    client_id: Optional[str] = None
    redirect_uri: str = ""
    response_type: Optional[ResponseType] = None
    state: str = ""
    scope: str = ""


@dataclass
class Post:
    grant_type: Optional[GrantType] = None
    redirect_uri: Optional[str] = None
    scope: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    refresh_token: Optional[str] = None
    code: Optional[str] = None


@dataclass
class Request:
    method: RequestMethod
    headers: Dict[str, str] = field(default_factory=dict)
    query: Query = Query()
    post: Post = Post()
    url: Any = ""
    user: Optional[Any] = None
