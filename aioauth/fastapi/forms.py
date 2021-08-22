"""
.. code-block:: python

    from aioauth.fastapi import forms

FastAPI oauth2 forms.

Used to generate an OpenAPI schema.

----
"""

from dataclasses import dataclass
from typing import Optional

from fastapi.params import Form

from aioauth.types import GrantType, TokenType


@dataclass
class TokenForm:
    grant_type: Optional[GrantType] = Form(None)
    client_id: Optional[str] = Form(None)
    client_secret: Optional[str] = Form(None)
    redirect_uri: Optional[str] = Form(None)
    scope: Optional[str] = Form(None)
    username: Optional[str] = Form(None)
    password: Optional[str] = Form(None)
    refresh_token: Optional[str] = Form(None)
    code: Optional[str] = Form(None)
    token: Optional[str] = Form(None)
    code_verifier: Optional[str] = Form(None)


@dataclass
class TokenIntrospectForm:
    token: Optional[str] = Form(None)
    token_type: Optional[TokenType] = Form(None)
