from typing import Any

from fastapi_oauth2.config import settings
from gino.ext.starlette import Gino
from sqlalchemy import Column, Integer

gino = Gino(dsn=settings.POSTGRES_DSN)


class Base(gino.Model):
    id: Any = Column(Integer, primary_key=True)  # noqa
    __name__: str
    __table__: Any
