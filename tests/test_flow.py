from http import HTTPStatus
from typing import Dict
from urllib.parse import parse_qsl, urlparse

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Post, Query, Request
from async_oauth2_provider.types import (
    CodeChallengeMethod,
    GrantType,
    RequestMethod,
    ResponseType,
)
from async_oauth2_provider.utils import create_s256_code_challenge, generate_token
from tests.conftest import Defaults
from tests.utils import check_params, set_authorization_headers


@pytest.mark.asyncio
async def test_plain_code_challenge(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    scope = defaults.scope
    state = generate_token(10)
    redirect_uri = defaults.redirect_uri
    request_url = "https://localhost"
    user = "username"

    query_params = {
        "client_id": defaults.client_id,
        "response_type": ResponseType.TYPE_CODE,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge_method": CodeChallengeMethod.PLAIN,
        "code_challenge": code_challenge,
    }

    query = Query(**query_params)

    request_params = {
        "url": request_url,
        "query": query,
        "method": RequestMethod.GET,
        "user": user,
    }

    request = Request(**request_params)

    await check_params(request_params, endpoint.create_authorization_code_response)

    response = await endpoint.create_authorization_code_response(request)

    assert response.status_code == HTTPStatus.FOUND

    # Get token
    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]

    post_params = {
        "grant_type": GrantType.TYPE_AUTHORIZATION_CODE,
        "redirect_uri": defaults.redirect_uri,
        "code": code,
        "code_verifier": code_challenge,
    }
    post = Post(**post_params)

    request_params = {
        "url": request_url,
        "post": post,
        "method": RequestMethod.POST,
        "headers": set_authorization_headers(client_id, client_secret),
    }

    request = Request(**request_params)

    await check_params(request_params, endpoint.create_token_response)

    response = await endpoint.create_token_response(request)

    assert response.status_code == HTTPStatus.OK

    access_token = response.content.access_token
    refresh_token = response.content.refresh_token

    post = Post(token=access_token)
    request = Request(
        url=request_url,
        post=post,
        method=RequestMethod.POST,
        headers=set_authorization_headers(client_id, client_secret),
    )
    response = await endpoint.create_token_introspection_response(request)
    assert response.status_code == HTTPStatus.OK

    post_params = {
        "grant_type": GrantType.TYPE_REFRESH_TOKEN,
        "refresh_token": refresh_token,
    }

    post = Post(**post_params)

    request_params = {
        "url": request_url,
        "post": post,
        "method": RequestMethod.POST,
        "headers": set_authorization_headers(client_id, client_secret),
    }

    request = Request(**request_params)

    await check_params(request_params, endpoint.create_token_response)
    response = await endpoint.create_token_response(request)

    assert response.status_code == HTTPStatus.OK
    assert response.content.access_token != access_token
    assert response.content.refresh_token != refresh_token

    tokens = storage.get("tokens", [])

    for token in tokens:
        if token.access_token == access_token and token.refresh_token == refresh_token:
            assert token.revoked


@pytest.mark.asyncio
async def test_pkce(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    code_verifier = generate_token(128)
    code_challenge = create_s256_code_challenge(code_verifier)
    request_url = "https://localhost"
    user = "username"

    query_params = {
        "client_id": defaults.client_id,
        "response_type": ResponseType.TYPE_CODE,
        "redirect_uri": defaults.redirect_uri,
        "scope": defaults.scope,
        "state": generate_token(10),
        "code_challenge_method": CodeChallengeMethod.S256,
        "code_challenge": code_challenge,
    }

    query = Query(**query_params)

    request_params = {
        "url": request_url,
        "query": query,
        "method": RequestMethod.GET,
        "user": user,
    }
    request = Request(**request_params)

    await check_params(request_params, endpoint.create_authorization_code_response)
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.FOUND

    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]
    post_params = {
        "grant_type": GrantType.TYPE_AUTHORIZATION_CODE,
        "redirect_uri": defaults.redirect_uri,
        "code": code,
        "code_verifier": code_verifier,
    }
    post = Post(**post_params)

    request_params = {
        "url": request_url,
        "post": post,
        "method": RequestMethod.POST,
        "headers": set_authorization_headers(client_id, client_secret),
    }

    request = Request(**request_params)

    await check_params(request_params, endpoint.create_token_response)
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_implicit_flow(endpoint: OAuth2Endpoint, defaults: Defaults):
    request_url = "https://localhost"
    user = "username"

    query_params = {
        "client_id": defaults.client_id,
        "response_type": ResponseType.TYPE_TOKEN,
        "redirect_uri": defaults.redirect_uri,
        "scope": defaults.scope,
        "state": generate_token(10),
    }

    query = Query(**query_params)

    request_params = {
        "url": request_url,
        "query": query,
        "method": RequestMethod.GET,
        "user": user,
    }
    request = Request(**request_params)

    await check_params(request_params, endpoint.create_authorization_code_response)

    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.FOUND


@pytest.mark.asyncio
async def test_password_grant_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post_params = {
        "grant_type": GrantType.TYPE_PASSWORD,
        "username": defaults.username,
        "password": defaults.password,
    }

    post = Post(**post_params)

    request_params = {
        "post": post,
        "url": request_url,
        "method": RequestMethod.POST,
        "headers": set_authorization_headers(client_id, client_secret),
    }

    request = Request(**request_params)

    await check_params(request_params, endpoint.create_token_response)
    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK


@pytest.mark.asyncio
async def test_authorization_code_flow(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"
    user = "username"

    query_params = {
        "client_id": defaults.client_id,
        "response_type": ResponseType.TYPE_CODE,
        "redirect_uri": defaults.redirect_uri,
        "scope": defaults.scope,
        "state": generate_token(10),
    }

    query = Query(**query_params)

    request_params = {
        "url": request_url,
        "query": query,
        "method": RequestMethod.GET,
        "user": user,
    }

    request = Request(**request_params)

    await check_params(request_params, endpoint.create_authorization_code_response)

    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.FOUND

    location = response.headers["location"]
    location = urlparse(location)
    query = dict(parse_qsl(location.query))
    code = query["code"]

    post_params = {
        "grant_type": GrantType.TYPE_AUTHORIZATION_CODE,
        "redirect_uri": defaults.redirect_uri,
        "code": code,
    }

    post = Post(**post_params)

    request_params = {
        "url": request_url,
        "post": post,
        "method": RequestMethod.POST,
        "headers": set_authorization_headers(client_id, client_secret),
    }

    request = Request(**request_params)

    await check_params(request_params, endpoint.create_token_response)

    response = await endpoint.create_token_response(request)
    assert response.status_code == HTTPStatus.OK
