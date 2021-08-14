from typing import NamedTuple


class Defaults(NamedTuple):
    client_id: str
    client_secret: str
    code: str
    refresh_token: str
    access_token: str
    username: str
    password: str
    redirect_uri: str
    scope: str
