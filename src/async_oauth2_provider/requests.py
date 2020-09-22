from typing import Any, Dict, Optional

from pydantic import BaseModel
from pydantic.networks import AnyHttpUrl

from .types import GrantType, RequestMethod, ResponseType


class Query(BaseModel):
    client_id: Optional[str]
    redirect_uri: Optional[AnyHttpUrl]
    response_type: Optional[ResponseType]
    state: str = ""
    scope: str = ""


class Post(BaseModel):
    grant_type: Optional[GrantType]
    redirect_uri: Optional[AnyHttpUrl]
    scope: Optional[str]
    username: Optional[str]
    password: Optional[str]
    refresh_token: Optional[str]
    code: Optional[str]


class Request(BaseModel):
    headers: Dict[str, str] = {}
    query: Query = Query()
    post: Post = Post()
    url: Any = ""
    method: RequestMethod = RequestMethod.POST
    # user: Optional[Any] = None

    class Config:
        orm_mode = True
