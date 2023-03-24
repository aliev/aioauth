"""
.. code-block:: python

    from aioauth import utils

Contains helper functions that is used throughout the project that doesn't
pertain to a specific file or module.

----
"""

import base64
from dataclasses import asdict

import binascii
import functools
import hashlib
import logging
import random
import string
from base64 import b64decode, b64encode
from http import HTTPStatus
from typing import (
    Any,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
)
from urllib.parse import quote, urlencode, urlparse, urlunsplit

from .collections import HTTPHeaderDict
from .errors import (
    OAuth2Error,
    ServerError,
    TemporarilyUnavailableError,
)
from .responses import ErrorResponse, Response

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


log = logging.getLogger(__name__)


def get_authorization_scheme_param(
    authorization_header_value: str,
) -> Tuple[str, str]:
    """
    Retrieves the authorization schema parameters from the authorization
    header.

    Args:
        authorization_header_value: Value of the authorization header.
    Returns:
        Tuple of the format ``(scheme, param)``.
    """
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def enforce_str(scope: List) -> str:
    """
    Converts a list of scopes to a space separated string.

    Note:
        If a string is passed to this method it will simply return an
        empty string back. Use :py:func:`enforce_list` to convert
        strings to scope lists.
    Args:
        scope: An iterable or string that contains a list of scope.
    Returns:
        A string of scopes seperated by spaces.
    Raises:
        TypeError: The ``scope`` value passed is not of the proper type.
    """
    if isinstance(scope, (set, tuple, list)):
        return " ".join([str(s) for s in scope])

    return ""


def enforce_list(scope: Optional[Union[str, List, Set, Tuple]]) -> List:
    """
    Converts a space separated string to a list of scopes.

    Note:
        If an iterable is passed to this method it will return a list
        representation of the iterable. Use :py:func:`enforce_str` to
        convert iterables to a scope string.
    Args:
        scope: An iterable or string that contains scopes.
    Returns:
        A list of scopes.
    """
    if isinstance(scope, (tuple, list, set)):
        return [str(s) for s in scope]
    elif scope is None:
        return []
    else:
        return scope.strip().split(" ")


def generate_token(length: int = 30, chars: str = UNICODE_ASCII_CHARACTER_SET) -> str:
    """Generates a non-guessable OAuth token.
    OAuth (1 and 2) does not specify the format of tokens except that
    they should be strings of random characters. Tokens should not be
    guessable and entropy when generating the random characters is
    important. Which is why SystemRandom is used instead of the default
    random.choice method.

    Args:
        length: Length of the generated token.
        chars: The characters to use to generate the string.
    Returns:
        Random string of length ``length`` and characters in ``chars``.
    """
    rand = random.SystemRandom()
    return "".join(rand.choice(chars) for _ in range(length))


def build_uri(
    url: str, query_params: Optional[Dict] = None, fragment: Optional[Dict] = None
) -> str:
    """
    Builds an URI string from passed ``url``, ``query_params``, and
    ``fragment``.

    Args:
        url: URL string.
        query_params: Paramaters that contain the query.
        fragment: Fragment of the page.
    Returns:
        URL containing the original ``url``, and the added
        ``query_params`` and ``fragment``.
    """
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
            urlencode(query_params, quote_via=quote),  # type: ignore
            urlencode(fragment, quote_via=quote),  # type: ignore
        )
    )
    return uri


def encode_auth_headers(client_id: str, client_secret: str) -> HTTPHeaderDict:
    """
    Encodes the authentication header using base64 encoding.

    Args:
        client_id: The client's id.
        client_secret: The client's secret.
    Returns:
        A case insensitive dictionary that contains the
        ``Authorization`` header set to ``basic`` and the authorization
        header.
    """
    authorization = b64encode(f"{client_id}:{client_secret}".encode("ascii"))
    return HTTPHeaderDict(Authorization=f"basic {authorization.decode()}")


def decode_auth_headers(authorization: str) -> Tuple[str, str]:
    """
    Decodes an encoded HTTP basic authentication string.
    Returns a tuple of the form ``(client_id, client_secret)``, and
    raises a :py:class:`aioauth.errors.InvalidClientError` exception if nothing
    could be decoded.

    Args:
        authorization: Authorization header string.
    Returns:
        Tuple of the form ``(client_id, client_secret)``.
    Raises:
        ValueError: Invalid `authorization` header string.
    """
    scheme, param = get_authorization_scheme_param(authorization)
    if not authorization or scheme.lower() != "basic":
        raise ValueError("Invalid authorization header string.")

    try:
        data = b64decode(param).decode("ascii")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("Invalid base64 encoding.") from exc

    client_id, separator, client_secret = data.partition(":")

    if not separator:
        raise ValueError("Separator was not provided.")

    return client_id, client_secret


def create_s256_code_challenge(code_verifier: str) -> str:
    """
    Create S256 code challenge with the passed ``code_verifier``.

    Note:
        This function implements
        ``base64url(sha256(ascii(code_verifier)))``.
    Args:
        code_verifier: Code verifier string.
    Returns:
        Representation of the S256 code challenge with the passed
        ``code_verifier``.
    """
    code_verifier_bytes = code_verifier.encode("utf-8")
    data = hashlib.sha256(code_verifier_bytes).digest()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def catch_errors_and_unavailability(
    skip_redirect_on_exc: Tuple[Type[OAuth2Error], ...] = (OAuth2Error,)
) -> Callable[..., Callable[..., Coroutine[Any, Any, Response]]]:
    """
    Decorator that adds error catching to the function passed.

    Args:
        f: A callable.
    Returns:
        A callable with error catching capabilities.
    """

    def decorator(f) -> Callable[..., Coroutine[Any, Any, Response]]:
        @functools.wraps(f)
        async def wrapper(self, request, *args, **kwargs) -> Response:
            error: Union[TemporarilyUnavailableError, ServerError]

            try:
                response = await f(self, request, *args, **kwargs)
            except skip_redirect_on_exc as exc:
                content = ErrorResponse(error=exc.error, description=exc.description)
                log.debug("%s %r", exc, request)
                return Response(
                    content=asdict(content),
                    status_code=exc.status_code,
                    headers=exc.headers,
                )
            except OAuth2Error as exc:
                log.debug("%s %r", exc, request)
                query: Dict[str, str] = {
                    "error": exc.error,
                }
                if exc.description:
                    query["error_description"] = exc.description
                if request.settings.ERROR_URI:
                    query["error_uri"] = request.settings.ERROR_URI
                location = build_uri(request.query.redirect_uri, query)
                return Response(
                    status_code=HTTPStatus.FOUND,
                    headers=HTTPHeaderDict({"location": location}),
                )
            except Exception:
                error = ServerError(request=request)
                log.exception("Exception caught while processing request.")
                content = ErrorResponse(
                    error=error.error, description=error.description
                )
                return Response(
                    content=asdict(content),
                    status_code=error.status_code,
                    headers=error.headers,
                )

            return response

        return wrapper

    return decorator
