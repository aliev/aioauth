from typing import AnyStr, List, Optional, Set, Tuple, Union

from async_oauth2_provider.config import settings


def is_secure_transport(uri) -> Union[AnyStr, bool]:
    """Check if the uri is over ssl."""
    if settings.INSECURE_TRANSPORT:
        return True
    return uri.lower().startswith("https://")


def get_authorization_scheme_param(
    authorization_header_value: AnyStr,
) -> Tuple[AnyStr, AnyStr]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def list_to_scope(scope: Optional[List] = None) -> Optional[AnyStr]:
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, str) or scope is None:
        return scope
    elif isinstance(scope, (set, tuple, list)):
        return " ".join([str(s) for s in scope])
    else:
        raise ValueError(
            "Invalid scope (%s), must be string, tuple, set, or list." % scope
        )


def scope_to_list(scope: Union[AnyStr, List, Set, Tuple]) -> Optional[List]:
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, (tuple, list, set)):
        return [str(s) for s in scope]
    elif scope is None:
        return None
    else:
        return scope.strip().split(" ")
