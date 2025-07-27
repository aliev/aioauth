"""
Different OAuth 2.0 responses with OpenID Connect extensions.

```python
from aioauth.oidc.core import responses
```
"""

from dataclasses import dataclass
from typing import Optional

from aioauth.responses import TokenResponse as OAuthTokenResponse


@dataclass
class TokenResponse(OAuthTokenResponse):
    """Token response extended with OpenID `id_token`"""

    id_token: Optional[str] = None
