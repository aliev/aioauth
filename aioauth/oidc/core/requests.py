from dataclasses import dataclass, field

from typing import Any, Optional, TypeVar

from aioauth.requests import (
    BaseRequest as BaseOAuth2Request,
    Query as OAuth2Query,
    Post,
    TPost,
    TUser,
)


@dataclass
class Query(OAuth2Query):
    # Space delimited, case sensitive list of ASCII string values that
    # specifies whether the Authorization Server prompts the End-User for
    # reauthentication and consent. The defined values are: none, login,
    # consent, select_account.
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    prompt: Optional[str] = None


TQuery = TypeVar("TQuery", bound=Query)


@dataclass
class BaseRequest(BaseOAuth2Request[TQuery, TPost, TUser]):
    """
    Object that contains a client's complete request with extensions as defined
    by OpenID Core.
    https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    """

    query: TQuery
    post: TPost
    user: Optional[TUser] = None


@dataclass
class Request(BaseRequest[Query, Post, Any]):
    """Object that contains a client's complete request."""

    query: Query = field(default_factory=Query)
    post: Post = field(default_factory=Post)
    user: Optional[Any] = None
