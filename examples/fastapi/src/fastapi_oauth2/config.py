from typing import Any, Dict, Optional

from pydantic import AnyHttpUrl, BaseSettings, PostgresDsn, validator


class Settings(BaseSettings):
    TESTING_ENV: bool = False
    SERVER_NAME: str
    SERVER_HOST: AnyHttpUrl
    PROJECT_NAME: str = "Async OAuth2 Provider"

    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_DSN: Optional[PostgresDsn] = None

    @validator("POSTGRES_DSN", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v

        path = "/{db}".format(db="{db}")

        if values.get("TESTING_ENV"):
            path = path.format(db=values.get("POSTGRES_DB") + "_test")
        else:
            path = path.format(db=values.get("POSTGRES_DB"))

        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            path=path,
        )

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
