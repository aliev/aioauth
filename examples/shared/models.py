"""
Database Models for OAuth2 Data Storage
"""

from typing import Optional, List
from sqlmodel import Field, SQLModel, Relationship


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    username: str = Field(unique=True, index=True)
    password: Optional[str] = None

    user_clients: List["Client"] = Relationship(back_populates="user")
    user_auth_codes: List["AuthorizationCode"] = Relationship(back_populates="user")
    user_tokens: List["Token"] = Relationship(back_populates="user")


class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    client_id: str = Field(unique=True, index=True)
    client_secret: Optional[str]
    grant_types: str
    response_types: str
    redirect_uris: str
    scope: str

    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: User = Relationship(back_populates="user_clients")


class AuthorizationCode(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    code: str
    client_id: str
    redirect_uri: str
    response_type: str
    scope: str
    auth_time: int
    expires_in: int
    code_challenge: Optional[str]
    code_challenge_method: Optional[str]
    nonce: Optional[str]

    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: User = Relationship(back_populates="user_auth_codes")


class Token(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    access_token: str
    refresh_token: str
    scope: str
    issued_at: int
    expires_in: int
    refresh_token_expires_in: int
    client_id: str
    token_type: str
    revoked: bool

    user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: User = Relationship(back_populates="user_tokens")
