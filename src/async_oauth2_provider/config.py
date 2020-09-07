from pydantic import BaseSettings


class Settings(BaseSettings):
    TOKEN_EXPIRES_IN: int = 86400
    AUTHORIZATION_CODE_EXPIRES_IN: int = 300
    INSECURE_TRANSPORT: bool = False

    class Config:
        env_file = ".env"
        env_prefix = "OAUTH2_"
        case_sensitive = True


settings = Settings()
