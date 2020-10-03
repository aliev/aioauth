from base64 import b64encode
from typing import Optional

from async_oauth2_provider.structures import CaseInsensitiveDict


def set_authorization_headers(
    username: str, password: str, headers: Optional[CaseInsensitiveDict] = None
) -> CaseInsensitiveDict:

    if headers is None:
        headers = CaseInsensitiveDict()

    authorization = b64encode(f"{username}:{password}".encode("ascii"))
    return CaseInsensitiveDict(
        **headers, Authorization=f"basic {authorization.decode()}"
    )
