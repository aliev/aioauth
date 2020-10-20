import os
from dataclasses import dataclass
from typing import Any, Callable


def get_env(env: str, default_value: Any, to_type: Callable, prefix="OAUTH2_"):
    """Get the value of an environment variable and apply a specific type to it"""
    return to_type(os.environ.get(f"{prefix}{env}", default_value))


@dataclass(frozen=True)
class Settings:
    TOKEN_EXPIRES_IN: int = get_env("TOKEN_EXPIRES_IN", 86400, int)
    AUTHORIZATION_CODE_EXPIRES_IN: int = get_env(
        "AUTHORIZATION_CODE_EXPIRES_IN", 300, int
    )
    INSECURE_TRANSPORT: bool = get_env("INSECURE_TRANSPORT", False, bool)
    ERROR_URI: str = get_env("ERROR_URI", "", str)


settings = Settings()
