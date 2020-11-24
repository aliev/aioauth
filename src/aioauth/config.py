from typing import NamedTuple


class Settings(NamedTuple):
    TOKEN_EXPIRES_IN: int = 86400
    AUTHORIZATION_CODE_EXPIRES_IN: int = 300
    INSECURE_TRANSPORT: bool = False
    ERROR_URI: str = ""
    AVAILABLE: bool = True
