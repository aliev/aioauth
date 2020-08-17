from typing import Tuple, Union
from async_oauth2_provider.config import oauth2_settings


def is_secure_transport(uri) -> Union[str, bool]:
    """Check if the uri is over ssl."""
    if oauth2_settings.INSECURE_TRANSPORT:
        return True
    return uri.lower().startswith("https://")


def get_authorization_scheme_param(authorization_header_value: str) -> Tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param
