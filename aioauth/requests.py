"""
.. code-block:: python

    from aioauth import requests

Request objects used throughout the project.

----
"""


from typing import Any, Optional, Text, NamedTuple

from .config import Settings
from .collections import HTTPHeaderDict
from .types import CodeChallengeMethod, GrantType, RequestMethod, ResponseMode


class Query(NamedTuple):
    """
    Object that contains a client's query string portion of a request.
    Read more on query strings `here <https://en.wikipedia.org/wiki/Query_string>`__.
    """

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
    """
    Object that contains a client's post request portion of a request.
    Read more on post requests `here <https://en.wikipedia.org/wiki/POST_(HTTP)>`__.
    """

    grant_type: Optional[GrantType] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    scope: str = ""
    username: Optional[Text] = None
    password: Optional[Text] = None
    refresh_token: Optional[str] = None
    code: Optional[str] = None
    token: Optional[str] = None
    code_verifier: Optional[str] = None


class Request(NamedTuple):
    """Object that contains a client's complete request."""

    method: RequestMethod
    headers: HTTPHeaderDict = HTTPHeaderDict()
    query: Query = Query()
    post: Post = Post()
    url: str = ""
    user: Optional[Any] = None
    settings: Settings = Settings()
