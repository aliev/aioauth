"""
Different OAuth 2.0 request with OpenID Connect extensions.

```python
from aioauth.oidc.core import requests
```
"""

from dataclasses import dataclass, field

from typing import Optional

from ...requests import (
    Request as BaseRequest,
    Query as BaseQuery,
)


@dataclass
class Query(BaseQuery):
    """Query extended with OpenID `prompt`"""

    # Space delimited, case sensitive list of ASCII string values that
    # specifies whether the Authorization Server prompts the End-User for
    # reauthentication and consent. The defined values are: none, login,
    # consent, select_account.
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    prompt: Optional[str] = None


@dataclass
class Request(BaseRequest):
    """Object that contains a client's complete request."""

    query: Query = field(default_factory=Query)
