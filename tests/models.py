from typing import NamedTuple, Text


class Defaults(NamedTuple):
    client_id: Text
    client_secret: Text
    code: Text
    refresh_token: Text
    access_token: Text
    username: Text
    password: Text
    redirect_uri: Text
    scope: Text
