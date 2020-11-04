from urllib.parse import urljoin

import pytest
from aioauth.errors import InvalidClientError
from aioauth.utils import (
    build_uri,
    decode_auth_headers,
    get_authorization_scheme_param,
    is_secure_transport,
    list_to_scope,
    scope_to_list,
)


def test_is_secure_transport(monkeypatch):
    monkeypatch.setenv("AIOAUTH_INSECURE_TRANSPORT", "1")

    is_secure = is_secure_transport("https://google.com")
    assert is_secure

    is_secure = is_secure_transport("http://google.com")
    assert is_secure


def test_get_authorization_scheme_param():
    assert get_authorization_scheme_param("") == ("", "")


def test_list_to_scope():
    assert list_to_scope("") == ""  # type: ignore
    assert list_to_scope(["read", "write"]) == "read write"
    with pytest.raises(ValueError):
        list_to_scope(1)  # type: ignore


def test_scope_to_list():
    assert scope_to_list("read write") == ["read", "write"]
    assert scope_to_list(["read", "write"]) == ["read", "write"]
    assert scope_to_list(None) == []  # type: ignore


def test_build_uri():
    build_uri("https://google.com") == "https://google.com"


def test_decode_auth_headers():
    with pytest.raises(InvalidClientError):
        decode_auth_headers("")

    with pytest.raises(InvalidClientError):
        decode_auth_headers("authorization")


def test_base_error_uri(monkeypatch):
    ERROR_URI = "https://google.com"
    monkeypatch.setenv("AIOAUTH_ERROR_URI", ERROR_URI)

    try:
        raise InvalidClientError()
    except InvalidClientError as exc:
        assert urljoin(ERROR_URI, exc.error) == exc.error_uri
