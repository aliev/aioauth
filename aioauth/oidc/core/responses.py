from dataclasses import dataclass
from typing import Optional

from aioauth.responses import TokenResponse as OAuthTokenResponse


@dataclass
class TokenResponse(OAuthTokenResponse):
    id_token: Optional[str] = None
