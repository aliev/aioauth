from base64 import b64encode
from urllib.parse import urljoin

import pytest

from aioauth.collections import HTTPHeaderDict
from aioauth.config import Settings
from aioauth.errors import InvalidClientError
from aioauth.requests import Request
from aioauth.utils import (
    build_uri,
    decode_auth_headers,
    enforce_list,
    enforce_str,
    get_authorization_scheme_param,
)


def test_get_authorization_scheme_param():
    assert get_authorization_scheme_param("") == ("", "")


def test_list_to_scope():
    assert enforce_str("") == ""  # type: ignore
    assert enforce_str(["read", "write"]) == "read write"


def test_scope_to_list():
    assert enforce_list("read write") == ["read", "write"]
    assert enforce_list(["read", "write"]) == ["read", "write"]
    assert enforce_list(None) == []  # type: ignore


def test_build_uri():
    build_uri("https://google.com") == "https://google.com"


def test_decode_auth_headers():
    request = Request(headers=HTTPHeaderDict(), method="POST")
    authorization = request.headers.get("Authorization", "")

    # No authorization header
    with pytest.raises(ValueError):
        decode_auth_headers("")

    # Invalid authorization header
    with pytest.raises(ValueError):
        decode_auth_headers("test")

    # No separator
    authorization = b64encode("usernamepassword".encode("ascii"))
    with pytest.raises(ValueError):
        decode_auth_headers(f"basic {authorization.decode()}")

    # No base64 digits
    with pytest.raises(ValueError):
        decode_auth_headers("basic привет")


def test_base_error_uri():
    ERROR_URI = "https://google.com"
    request = Request(settings=Settings(ERROR_URI=ERROR_URI), method="POST")

    try:
        raise InvalidClientError(request=request)
    except InvalidClientError as exc:
        assert urljoin(ERROR_URI, exc.error) == exc.error_uri
