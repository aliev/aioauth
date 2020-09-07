from base64 import b64encode
from http import HTTPStatus

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Query, Request
from async_oauth2_provider.types import GrantType, RequestMethod, ResponseType
from tests.conftest import Defaults

# from urllib.parse import urlparse


@pytest.mark.asyncio
async def test_response_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    post = Post(username=defaults.username, password=defaults.password)
    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_TOKEN,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state="test",
    )
    request = Request(
        url="https://google.com/", post=post, query=query, method=RequestMethod.POST
    )

    response = await endpoint.create_authorization_response(request)
    # redirect_uri = urlparse(response.headers["location"])

    request = Request(
        url="https://google.com/",
        post=Post(username="admin", password="admin"),
        query=Query(
            client_id=defaults.client_id,
            response_type=ResponseType.TYPE_TOKEN,
            redirect_uri=defaults.redirect_uri,
            scope="hello",
            state="test",
        ),
        method="GET",
    )

    response = await endpoint.create_authorization_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_grant_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    """ Simple smoke test """
    post = Post(
        grant_type=GrantType.TYPE_AUTHORIZATION_CODE,
        redirect_uri=defaults.redirect_uri,
        code=defaults.code,
    )
    authorization = b64encode(
        f"{defaults.client_id}:{defaults.client_secret}".encode("ascii")
    )
    headers = {"Authorization": f"basic {authorization.decode()}"}
    request = Request(
        url="https://google.com", post=post, method=RequestMethod.POST, headers=headers
    )
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


# @pytest.mark.asyncio
# async def test_authorization_code_grant_type():
#     request = Request(
#         url="https://google.com/",
#         post=Post(username="admin", password="admin"),
#         query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
#         method="POST"
#     )

#     token_endpoint = OAuth2Endpoint(db_class=DB)

#     response = await token_endpoint.create_authorization_response(request)
#     assert response.status_code == HTTPStatus.FOUND

#     request = Request(
#         url="https://google.com/",
#         post=Post(username="admin", password="admin"),
#         query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
#         method="GET"
#     )

#     token_endpoint = OAuth2Endpoint(db_class=DB)

#     response = await token_endpoint.create_authorization_response(request)
#     assert response.status_code == HTTPStatus.OK


# @pytest.mark.asyncio
# async def test_invalid_username_or_password():
#     request = Request(
#         url="https://google.com/",
#         post=Post(username="admin1", password="admin1"),
#         query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
#         method="POST"
#     )

#     token_endpoint = OAuth2Endpoint(db_class=DB)

#     response = await token_endpoint.create_authorization_response(request)
#     assert response.status_code == HTTPStatus.BAD_REQUEST

#     request = Request(
#         url="https://google.com/",
#         post=Post(username="", password=""),
#         query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
#         method="POST"
#     )

#     token_endpoint = OAuth2Endpoint(db_class=DB)

#     response = await token_endpoint.create_authorization_response(request)
#     assert response.status_code == HTTPStatus.BAD_REQUEST

#     request = Request(
#         url="https://google.com/",
#         post=Post(username="123", password=""),
#         query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
#         method="POST"
#     )

#     token_endpoint = OAuth2Endpoint(db_class=DB)

#     response = await token_endpoint.create_authorization_response(request)
#     assert response.status_code == HTTPStatus.BAD_REQUEST


# @pytest.mark.asyncio
# async def test_insecure_connection():
#     request = Request(
#         url="http://google.com/",
#         post=Post(username="admin", password="admin"),
#         query=Query(client_id=CLIENT_ID, response_type="code", redirect_uri=REDIRECT_URI, scope="hello", state="test"),
#         method="POST"
#     )

#     token_endpoint = OAuth2Endpoint(db_class=DB)

#     response = await token_endpoint.create_authorization_response(request)
#     assert response.status_code == HTTPStatus.BAD_REQUEST
