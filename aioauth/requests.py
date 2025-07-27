"""
Request objects used throughout the project.
```python
from aioauth import requests
```
"""

from dataclasses import dataclass, field
from typing import Optional

from .collections import HTTPHeaderDict
from .config import Settings
from .types import (
    CodeChallengeMethod,
    GrantType,
    RequestMethod,
    ResponseMode,
    TokenType,
)


@dataclass
class Query:
    """
    Object that contains a client's query string portion of a request.
    Read more on query strings [here](https://en.wikipedia.org/wiki/Query_string).
    """

    client_id: Optional[str] = None
    redirect_uri: str = ""
    response_type: Optional[str] = None
    state: str = ""
    scope: str = ""
    nonce: Optional[str] = None
    code_challenge_method: Optional[CodeChallengeMethod] = None
    code_challenge: Optional[str] = None
    response_mode: Optional[ResponseMode] = None


@dataclass
class Post:
    """
    Object that contains a client's post request portion of a request.
    Read more on post requests [here](https://en.wikipedia.org/wiki/POST_(HTTP)).
    """

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
    token_type_hint: Optional[TokenType] = None
    code_verifier: Optional[str] = None


@dataclass
class Request:
    """Object that contains a client's complete request."""

    method: RequestMethod
    query: Query = field(default_factory=Query)
    post: Post = field(default_factory=Post)
    headers: HTTPHeaderDict = field(default_factory=HTTPHeaderDict)
    url: str = ""
    settings: Settings = field(default_factory=Settings)
    extra: dict = field(default_factory=dict)
