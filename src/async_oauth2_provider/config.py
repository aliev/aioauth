import os
from dataclasses import dataclass
from typing import Any, Callable


def get_env(env: str, default_value: Any, to_type: Callable):
    """Get the value of an environment variable and apply a specific type to it
    """
    return to_type(os.environ.get(env, default_value))


@dataclass(frozen=True)
class Settings:
    TOKEN_EXPIRES_IN: int = get_env("OAUTH2_TOKEN_EXPIRES_IN", 86400, int)
    AUTHORIZATION_CODE_EXPIRES_IN: int = get_env(
        "OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN", 300, int
    )
    INSECURE_TRANSPORT: bool = get_env("OAUTH2_INSECURE_TRANSPORT", False, bool)


settings = Settings()
