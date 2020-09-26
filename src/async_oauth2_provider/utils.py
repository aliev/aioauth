import base64
import binascii
import hashlib
import random
import string
from base64 import b64decode
from typing import List, Optional, Set, Text, Tuple, Union
from urllib.parse import quote, urlencode, urlparse, urlunsplit

from async_oauth2_provider.exceptions import InvalidCredentialsError
from async_oauth2_provider.requests import Request

from .config import settings

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


def is_secure_transport(uri: str) -> bool:
    """Check if the uri is over ssl.
    """
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
    """Convert a list of scopes to a space separated string.
    """
    if isinstance(scope, str) or scope is None:
        return ""
    elif isinstance(scope, (set, tuple, list)):
        return " ".join([str(s) for s in scope])
    else:
        raise ValueError(
            "Invalid scope (%s), must be string, tuple, set, or list." % scope
        )


def scope_to_list(scope: Union[Text, List, Set, Tuple]) -> List:
    """Convert a space separated string to a list of scopes.
    """
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

    scheme, param = get_authorization_scheme_param(authorization)

    if not authorization or scheme.lower() != "basic":
        raise InvalidCredentialsError()

    try:
        data = b64decode(param).decode("ascii")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise InvalidCredentialsError()

    client_id, separator, client_secret = data.partition(":")

    if not separator:
        raise InvalidCredentialsError()

    return client_id, client_secret


def create_s256_code_challenge(code_verifier: str) -> str:
    """Create S256 code_challenge with the given code_verifier.

    Implements:
        base64url(sha256(ascii(code_verifier)))
    """
    code_verifier_bytes = code_verifier.encode("utf-8")
    data = hashlib.sha256(code_verifier_bytes).digest()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
