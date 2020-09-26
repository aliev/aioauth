from dataclasses import dataclass, field
from typing import Any, Optional

from .structures import CaseInsensitiveDict
from .types import CodeChallengeMethod, GrantType, RequestMethod, ResponseType


@dataclass
class Query:
    client_id: Optional[str] = None
    redirect_uri: str = ""
    response_type: Optional[ResponseType] = None
    state: str = ""
    scope: str = ""
    code_challenge_method: Optional[CodeChallengeMethod] = None
    code_challenge: Optional[str] = None


@dataclass
class Post:
    grant_type: Optional[GrantType] = None
    redirect_uri: Optional[str] = None
    scope: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    refresh_token: Optional[str] = None
    code: Optional[str] = None
    token: Optional[str] = None
    code_verifier: Optional[str] = None


@dataclass
class Request:
    method: RequestMethod
    headers: CaseInsensitiveDict = field(default_factory=lambda: CaseInsensitiveDict())
    query: Query = Query()
    post: Post = Post()
    url: Any = ""
    user: Optional[Any] = None
