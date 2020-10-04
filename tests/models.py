from typing import Text

from pydantic.main import BaseModel
from pydantic.networks import AnyHttpUrl


class Defaults(BaseModel):
    client_id: Text
    client_secret: Text
    code: Text
    refresh_token: Text
    access_token: Text
    username: Text
    password: Text
    redirect_uri: AnyHttpUrl
    scope: Text
