"""
Global Example Configuration Settings
"""

from typing import List

from pydantic import BaseModel
from aioauth.config import Settings

from .models import User, Client


def load_config(fpath: str) -> "Config":
    """load configuration from filepath"""
    with open(fpath, "r") as f:
        json = f.read()
        return Config.model_validate_json(json)


class Fixtures(BaseModel):
    users: List[User]
    clients: List[Client]


class Config(BaseModel):
    fixtures: Fixtures
    settings: Settings
