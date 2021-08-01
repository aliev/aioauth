from typing import Any, NamedTuple, Optional

from .config import Settings
from .structures import CaseInsensitiveDict
from .types import CodeChallengeMethod, GrantType, RequestMethod, ResponseMode


class Query(NamedTuple):
    client_id: Optional[str] = None
    redirect_uri: str = ""
    response_type: str = ""
    state: str = ""
    scope: str = ""
    nonce: Optional[str] = None
    code_challenge_method: Optional[CodeChallengeMethod] = None
    code_challenge: Optional[str] = None
    response_mode: Optional[ResponseMode] = None


class Post(NamedTuple):
    grant_type: Optional[GrantType] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    scope: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    refresh_token: Optional[str] = None
    code: Optional[str] = None
    token: Optional[str] = None
    code_verifier: Optional[str] = None


class Request(NamedTuple):
    method: RequestMethod
    headers: CaseInsensitiveDict = CaseInsensitiveDict()
    query: Query = Query()
    post: Post = Post()
    url: str = ""
    user: Optional[Any] = None
    settings: Settings = Settings()
