"""
.. code-block:: python

    from aioauth import requests

Request objects used throughout the project.

----
"""


from types import SimpleNamespace
from typing import Any, Optional, Text

from .config import Settings
from .structures import CaseInsensitiveDict
from .types import CodeChallengeMethod, GrantType, RequestMethod, ResponseType


class Query(SimpleNamespace):
    """
    Object that contains a client's query string portion of a request.
    Read more on query strings `here <https://en.wikipedia.org/wiki/Query_string>`__.
    """

    client_id: Optional[str] = None
    redirect_uri: str = ""
    response_type: Optional[ResponseType] = None
    state: str = ""
    scope: str = ""
    code_challenge_method: Optional[CodeChallengeMethod] = None
    code_challenge: Optional[str] = None


class Post(SimpleNamespace):
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


class Request(SimpleNamespace):
    """Object that contains a client's complete request."""

    method: RequestMethod
    headers: CaseInsensitiveDict = CaseInsensitiveDict()
    query: Query = Query()
    post: Post = Post()
    url: str = ""
    user: Optional[Any] = None
    settings: Settings = Settings()
