from urllib.parse import urljoin

import pytest
from aioauth.config import Settings
from aioauth.errors import InvalidClientError
from aioauth.requests import Request
from aioauth.structures import CaseInsensitiveDict
from aioauth.types import RequestMethod
from aioauth.utils import (
    build_uri,
    decode_auth_headers,
    get_authorization_scheme_param,
    is_secure_transport,
    list_to_scope,
    scope_to_list,
)


def test_is_secure_transport():
    request = Request(method=RequestMethod.GET, url="https://google.com")

    is_secure = is_secure_transport(request=request)
    assert is_secure

    request = Request(method=RequestMethod.GET, url="http://google.com")
    is_secure = is_secure_transport(request=request)
    assert not is_secure


def test_is_secure_transport_insecure_transport_enabled():
    request = Request(
        method=RequestMethod.GET,
        url="https://google.com",
        settings=Settings(INSECURE_TRANSPORT=True),
    )

    is_secure = is_secure_transport(request=request)
    assert is_secure

    request = Request(
        method=RequestMethod.GET,
        url="https://google.com",
        settings=Settings(INSECURE_TRANSPORT=True),
    )
    is_secure = is_secure_transport(request=request)
    assert is_secure


def test_get_authorization_scheme_param():
    assert get_authorization_scheme_param("") == ("", "")


def test_list_to_scope():
    assert list_to_scope("") == ""  # type: ignore
    assert list_to_scope(["read", "write"]) == "read write"
    with pytest.raises(TypeError):
        list_to_scope(1)  # type: ignore


def test_scope_to_list():
    assert scope_to_list("read write") == ["read", "write"]
    assert scope_to_list(["read", "write"]) == ["read", "write"]
    assert scope_to_list(None) == []  # type: ignore


def test_build_uri():
    build_uri("https://google.com") == "https://google.com"


def test_decode_auth_headers():
    request = Request(headers=CaseInsensitiveDict(), method=RequestMethod.POST)
    with pytest.raises(InvalidClientError):
        decode_auth_headers(request=request)

    request = Request(
        headers=CaseInsensitiveDict({"authorization": ""}), method=RequestMethod.POST,
    )
    with pytest.raises(InvalidClientError):
        decode_auth_headers(request=request)


def test_base_error_uri():
    ERROR_URI = "https://google.com"
    request = Request(settings=Settings(ERROR_URI=ERROR_URI), method=RequestMethod.POST)

    try:
        raise InvalidClientError(request=request)
    except InvalidClientError as exc:
        assert urljoin(ERROR_URI, exc.error) == exc.error_uri
