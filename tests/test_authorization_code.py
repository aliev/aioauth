from http import HTTPStatus
from .db import CLIENT_ID, DB, REDIRECT_URI
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Query, Request
import pytest


@pytest.mark.asyncio
async def test_implicit_grant_type():
    request = Request(
        url="https://google.com/",
        post=Post(username="admin", password="admin"),
        query=Query(client_id=CLIENT_ID, response_type="token", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="POST"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.SEE_OTHER

    request = Request(
        url="https://google.com/",
        post=Post(username="admin", password="admin"),
        query=Query(client_id=CLIENT_ID, response_type="token", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="GET"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_authorization_code_grant_type():
    request = Request(
        url="https://google.com/",
        post=Post(username="admin", password="admin"),
        query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="POST"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.SEE_OTHER

    request = Request(
        url="https://google.com/",
        post=Post(username="admin", password="admin"),
        query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="GET"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_invalid_username_or_password():
    request = Request(
        url="https://google.com/",
        post=Post(username="admin1", password="admin1"),
        query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="POST"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    request = Request(
        url="https://google.com/",
        post=Post(username="", password=""),
        query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="POST"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    request = Request(
        url="https://google.com/",
        post=Post(username="123", password=""),
        query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="POST"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_insecure_connection():
    request = Request(
        url="http://google.com/",
        post=Post(username="admin", password="admin"),
        query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
        method="POST"
    )

    token_endpoint = OAuth2Endpoint(db_class=DB)

    response = await token_endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
