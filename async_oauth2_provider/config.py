from pathlib import Path
from typing import Optional

from pydantic import BaseSettings, DirectoryPath, validator


class Settings(BaseSettings):
    TOKEN_EXPIRES_IN: int = 86400
    AUTHORIZATION_CODE_EXPIRES_IN: int = 300
    LOGIN_TEMPLATE_PATH: Optional[DirectoryPath]
    INSECURE_TRANSPORT: bool = False

    @validator("LOGIN_TEMPLATE_PATH", pre=True)
    def setup_default_template_path(cls, value):
        here = Path(__file__).parent

        if not value:
            return here / "templates"

        return value

    class Config:
        env_file = ".env"
        env_prefix = "OAUTH2_"
        case_sensitive = True


settings = Settings()
