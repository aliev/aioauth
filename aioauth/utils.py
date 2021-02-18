import base64
import binascii
import functools
import hashlib
import logging
import random
import string
from base64 import b64decode, b64encode
from typing import Callable, Dict, List, Optional, Set, Text, Tuple, Union
from urllib.parse import quote, urlencode, urlparse, urlunsplit

from .errors import (
    InvalidClientError,
    OAuth2Error,
    ServerError,
    TemporarilyUnavailableError,
)
from .requests import Request
from .responses import ErrorResponse, Response
from .structures import CaseInsensitiveDict

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


log = logging.getLogger(__name__)


def is_secure_transport(request: Request) -> bool:
    """Check if the uri is over ssl."""
    if request.settings.INSECURE_TRANSPORT:
        return True
    return request.url.lower().startswith("https://")


def get_authorization_scheme_param(
    authorization_header_value: Text,
) -> Tuple[Text, Text]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def list_to_scope(scope: Optional[List] = None) -> Text:
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, str) or scope is None:
        return ""
    elif isinstance(scope, (set, tuple, list)):
        return " ".join([str(s) for s in scope])
    else:
        raise ValueError(
            "Invalid scope (%s), must be string, tuple, set, or list." % scope
        )


def scope_to_list(scope: Union[Text, List, Set, Tuple]) -> List:
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, (tuple, list, set)):
        return [str(s) for s in scope]
    elif scope is None:
        return []
    else:
        return scope.strip().split(" ")


def generate_token(length: int = 30, chars: str = UNICODE_ASCII_CHARACTER_SET) -> str:
    """Generates a non-guessable OAuth token

    OAuth (1 and 2) does not specify the format of tokens except that they
    should be strings of random characters. Tokens should not be guessable
    and entropy when generating the random characters is important. Which is
    why SystemRandom is used instead of the default random.choice method.
    """
    rand = random.SystemRandom()
    return "".join(rand.choice(chars) for _ in range(length))


def build_uri(
    url: str, query_params: Optional[Dict] = None, fragment: Optional[Dict] = None
) -> str:
    """Build uri string from given url, query_params and fragment"""
    if query_params is None:
        query_params = {}

    if fragment is None:
        fragment = {}

    parsed_url = urlparse(url)
    uri = urlunsplit(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            urlencode(query_params, quote_via=quote),
            urlencode(fragment, quote_via=quote),
        )
    )
    return uri


def encode_auth_headers(client_id: str, client_secret: str) -> CaseInsensitiveDict:
    authorization = b64encode(f"{client_id}:{client_secret}".encode("ascii"))
    return CaseInsensitiveDict(Authorization=f"basic {authorization.decode()}")


def decode_auth_headers(request: Request) -> Tuple[str, str]:
    """Decode an encrypted HTTP basic authentication string. Returns a tuple of
    the form (client_id, client_secret), and raises a InvalidClientError exception if
    nothing could be decoded.
    """
    authorization = request.headers.get("Authorization", "")

    headers = CaseInsensitiveDict({"WWW-Authenticate": "Basic"})

    scheme, param = get_authorization_scheme_param(authorization)
    if not authorization or scheme.lower() != "basic":
        raise InvalidClientError(request=request, headers=headers)

    try:
        data = b64decode(param).decode("ascii")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise InvalidClientError(request=request, headers=headers)

    client_id, separator, client_secret = data.partition(":")

    if not separator:
        raise InvalidClientError(request=request, headers=headers)

    return client_id, client_secret


def create_s256_code_challenge(code_verifier: str) -> str:
    """Create S256 code_challenge with the given code_verifier.

    Implements:
        base64url(sha256(ascii(code_verifier)))
    """
    code_verifier_bytes = code_verifier.encode("utf-8")
    data = hashlib.sha256(code_verifier_bytes).digest()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def catch_errors_and_unavailability(f) -> Callable:
    @functools.wraps(f)
    async def wrapper(self, request: Request, *args, **kwargs) -> Optional[Response]:
        if not request.settings.AVAILABLE:
            error = TemporarilyUnavailableError(request=request)
            content = ErrorResponse(error=error.error, description=error.description)
            return Response(
                content=content, status_code=error.status_code, headers=error.headers
            )

        try:
            response = await f(self, request, *args, **kwargs)
            return response
        except OAuth2Error as exc:
            content = ErrorResponse(error=exc.error, description=exc.description)
            log.debug(exc)
            return Response(
                content=content, status_code=exc.status_code, headers=exc.headers
            )
        except Exception:
            error = ServerError(request=request)
            log.exception("Exception caught while processing request.")
            content = ErrorResponse(error=error.error, description=error.description)
            return Response(
                content=content, status_code=error.status_code, headers=error.headers,
            )

    return wrapper
