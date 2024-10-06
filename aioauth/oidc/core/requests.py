from dataclasses import dataclass, field

from typing import Optional

from aioauth.requests import (
    BaseRequest,
    Query as OAuth2Query,
    TUser,
)


@dataclass
class Query(OAuth2Query):
    # Space delimited, case sensitive list of ASCII string values that
    # specifies whether the Authorization Server prompts the End-User for
    # reauthentication and consent. The defined values are: none, login,
    # consent, select_account.
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    prompt: Optional[str] = None


@dataclass
class Request(BaseRequest[TUser]):
    """Object that contains a client's complete request."""

    query: Query = field(default_factory=Query)
