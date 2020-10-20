import base64
import binascii
import functools
import hashlib
import logging
import random
import string
from base64 import b64decode
from typing import List, Optional, Set, Text, Tuple, Union
from urllib.parse import quote, urlencode, urlparse, urlunsplit

from .config import settings
from .exceptions import (
    InvalidClientError,
    OAuth2Exception,
    ServerError,
    TemporarilyUnavailableError,
)
from .requests import Request
from .responses import ErrorResponse, Response
from .structures import CaseInsensitiveDict

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


log = logging.getLogger(__name__)


def is_secure_transport(uri: str) -> bool:
    """Check if the uri is over ssl."""
    if settings.INSECURE_TRANSPORT:
        return True
    return uri.lower().startswith("https://")


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


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    """Generates a non-guessable OAuth token

    OAuth (1 and 2) does not specify the format of tokens except that they
    should be strings of random characters. Tokens should not be guessable
    and entropy when generating the random characters is important. Which is
    why SystemRandom is used instead of the default random.choice method.
    """
    rand = random.SystemRandom()
    return "".join(rand.choice(chars) for _ in range(length))


def build_uri(url: str, query_params: dict = None, fragment: dict = None) -> str:
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


def check_basic_auth(request: Request) -> Tuple[str, str]:
    authorization: str = request.headers.get("Authorization", "")
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


def catch_errors_and_unavailability(f):
    @functools.wraps(f)
    async def wrapper(endpoint, *args, **kwargs):
        if not endpoint.available:
            error = TemporarilyUnavailableError()
            content = ErrorResponse(error=error.error, description=error.description)
            return Response(
                content=content, status_code=error.status_code, headers=error.headers
            )

        try:
            response = await f(endpoint, *args, **kwargs)
            return response
        except OAuth2Exception as exc:
            content = ErrorResponse(error=exc.error, description=exc.description)
            log.debug(exc)
            return Response(
                content=content, status_code=exc.status_code, headers=exc.headers
            )
        except Exception:
            if endpoint.catch_errors:
                error = ServerError()
                log.exception("Exception caught while processing request.")
                content = ErrorResponse(
                    error=error.error, description=error.description
                )
                return Response(
                    content=content,
                    status_code=error.status_code,
                    headers=error.headers,
                )
            else:
                raise

    return wrapper
