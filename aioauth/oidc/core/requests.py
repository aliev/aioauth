from dataclasses import dataclass, field

from typing import Any, Optional

from aioauth.requests import BaseRequest, Query as BaseQuery, Post


@dataclass
class Query(BaseQuery):
    prompt: Optional[str] = None


@dataclass
class Request(BaseRequest[Query, Post, Any]):
    """Object that contains a client's complete request."""

    query: Query = field(default_factory=Query)
    post: Post = field(default_factory=Post)
    user: Optional[Any] = None
