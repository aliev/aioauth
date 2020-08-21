from enum import Enum
from typing import Any, Optional
from async_oauth2_provider.types import GrantType, RequestMethod, ResponseType
from pydantic import BaseModel
from pydantic.networks import AnyHttpUrl


class Query(BaseModel):
    client_id: Optional[str]
    redirect_uri: Optional[AnyHttpUrl]
    response_type: Optional[ResponseType]
    state: Optional[str]
    scope: Optional[str]


class Post(BaseModel):
    grant_type: Optional[GrantType]
    redirect_uri: Optional[AnyHttpUrl]
    scope: Optional[str]
    username: Optional[str]
    password: Optional[str]
    refresh_token: Optional[str]
    code: Optional[str]


class Request(BaseModel):
    headers: dict = {}
    query: Optional[Query] = Query()
    post: Optional[Post] = Post()
    url: Optional[AnyHttpUrl]
    method: RequestMethod = RequestMethod.POST
    user: Any
