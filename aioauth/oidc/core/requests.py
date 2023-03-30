from dataclasses import dataclass, field

from typing import Any, Optional, TypeVar

from aioauth.requests import BaseRequest, Query as BaseQuery, Post


@dataclass
class Query(BaseQuery):
    # Space delimited, case sensitive list of ASCII string values that
    # specifies whether the Authorization Server prompts the End-User for
    # reauthentication and consent. The defined values are: none, login,
    # consent, select_account.
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    prompt: Optional[str] = None


@dataclass
class Request(BaseRequest[Query, Post, Any]):
    """
    Object that contains a client's complete request with extensions as defined
    by OpenID Core.
    https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    """

    query: Query = field(default_factory=Query)
    post: Post = field(default_factory=Post)
    user: Optional[Any] = None


TRequest = TypeVar("TRequest", bound=Request)
