import os
from typing import Any, Callable, NamedTuple


def get_env(env: str, default_value: Any, to_type: Callable, prefix="AIOAUTH_"):
    """Get the value of an environment variable and apply a specific type to it"""
    return to_type(os.environ.get(f"{prefix}{env}", default_value))


class Settings(NamedTuple):
    TOKEN_EXPIRES_IN: int
    AUTHORIZATION_CODE_EXPIRES_IN: int
    INSECURE_TRANSPORT: bool
    ERROR_URI: str


def get_settings():
    return Settings(
        TOKEN_EXPIRES_IN=get_env("TOKEN_EXPIRES_IN", 86400, int),
        AUTHORIZATION_CODE_EXPIRES_IN=get_env(
            "AUTHORIZATION_CODE_EXPIRES_IN", 300, int
        ),
        INSECURE_TRANSPORT=get_env("INSECURE_TRANSPORT", False, bool),
        ERROR_URI=get_env("ERROR_URI", "", str),
    )
