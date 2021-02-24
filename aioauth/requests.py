from types import SimpleNamespace
from typing import Any, Optional, Text

from .config import Settings
from .structures import CaseInsensitiveDict
from .types import CodeChallengeMethod, GrantType, RequestMethod, ResponseType


class Query(SimpleNamespace):
    client_id: Optional[str] = None
    redirect_uri: str = ""
    response_type: Optional[ResponseType] = None
    state: str = ""
    scope: str = ""
    code_challenge_method: Optional[CodeChallengeMethod] = None
    code_challenge: Optional[str] = None


class Post(SimpleNamespace):
    grant_type: Optional[GrantType] = None
    redirect_uri: Optional[str] = None
    scope: str = ""
    username: Optional[Text] = None
    password: Optional[Text] = None
    refresh_token: Optional[str] = None
    code: Optional[str] = None
    token: Optional[str] = None
    code_verifier: Optional[str] = None


class Request(SimpleNamespace):
    method: RequestMethod
    headers: CaseInsensitiveDict = CaseInsensitiveDict()
    query: Query = Query()
    post: Post = Post()
    url: str = ""
    user: Optional[Any] = None
    settings: Settings = Settings()
