import json
import time

import sqlalchemy as db
from fastapi_oauth2.db import Base
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property


class ClientTable(Base):
    __tablename__ = "oauth2_client"

    client_id = db.Column(db.String(48), index=True)
    client_secret = db.Column(db.String(120))
    client_id_issued_at = db.Column(db.Integer, nullable=False, default=0)
    client_secret_expires_at = db.Column(db.Integer, nullable=False, default=0)
    _client_metadata = db.Column("client_metadata", db.Text)

    @hybrid_property
    def client_metadata(self):
        if self._client_metadata:
            return json.loads(self._client_metadata)
        return {}

    @hybrid_method
    def set_client_metadata(self, value):
        self._client_metadata = json.dumps(value)


class AuthorizationCodeTable(Base):
    __tablename__ = "oauth2_authorization_code"

    code = db.Column(db.String(120), unique=True, nullable=False)
    client_id = db.Column(db.String(48))
    redirect_uri = db.Column(db.Text, default="")
    response_type = db.Column(db.Text, default="")
    scope = db.Column(db.Text, default="")
    nonce = db.Column(db.Text)
    auth_time = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))

    code_challenge = db.Column(db.Text)
    code_challenge_method = db.Column(db.String(48))


class TokenTable(Base):
    __tablename__ = "oauth2_token"

    client_id = db.Column(db.String(48))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True, nullable=False)
    refresh_token = db.Column(db.String(255), index=True)
    scope = db.Column(db.Text, default="")
    revoked = db.Column(db.Boolean, default=False)
    issued_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    expires_in = db.Column(db.Integer, nullable=False, default=0)
