from http import HTTPStatus

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Query, Request
from async_oauth2_provider.types import CodeChallengeMethod, RequestMethod, ResponseType
from async_oauth2_provider.utils import generate_token

from .conftest import Defaults


@pytest.mark.asyncio
async def test_anonymous_user(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    redirect_uri = defaults.redirect_uri
    scope = defaults.scope
    request_url = "https://localhost"

    query = Query(
        client_id=client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )
    request = Request(url=request_url, query=query, method=RequestMethod.GET,)
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_invalid_response_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    redirect_uri = defaults.redirect_uri
    scope = defaults.scope
    request_url = "https://localhost"
    user = "username"
    response_type = "invalid"

    query = Query(
        client_id=client_id,
        response_type=response_type,  # type: ignore
        redirect_uri=redirect_uri,
        scope=scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_empty_client_id(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    redirect_uri = defaults.redirect_uri
    scope = defaults.scope
    request_url = "https://localhost"
    user = "username"

    query = Query(
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_empty_redirect_uri(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    scope = defaults.scope
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=client_id,
        response_type=ResponseType.TYPE_CODE,
        scope=scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_invalid_client_id(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    redirect_uri = defaults.redirect_uri
    client_id = "invalid"
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_insecure_transport(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    redirect_uri = defaults.redirect_uri
    scope = defaults.scope
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id="invalid",
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_allowed_method(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    request_url = "https://localhost"
    user = "username"
    state = generate_token(10)
    scope = defaults.scope
    redirect_uri = defaults.redirect_uri

    query = Query(
        client_id=client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.POST, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED
    assert RequestMethod.GET in response.headers["allow"]


@pytest.mark.asyncio
async def test_invalid_code_challange_method(
    endpoint: OAuth2Endpoint, defaults: Defaults
):
    state = generate_token(10)
    code_challenge = generate_token(128)
    code_challenge_method = "invalid"
    scope = defaults.scope
    redirect_uri = defaults.redirect_uri
    request_url = "https://localhost"

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge_method=code_challenge_method,  # type: ignore
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_empty_code_challange(endpoint: OAuth2Endpoint, defaults: Defaults):
    client_id = defaults.client_id
    redirect_uri = defaults.redirect_uri
    scope = defaults.scope
    state = generate_token(10)
    request_url = "https://localhost"
    user = "username"

    query = Query(
        client_id=client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge_method=CodeChallengeMethod.PLAIN,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_empty_response_type(endpoint: OAuth2Endpoint, defaults: Defaults):
    code_challenge = generate_token(128)
    client_id = defaults.client_id
    redirect_uri = defaults.redirect_uri
    scope = defaults.scope
    request_url = "https://localhost"
    user = "username"
    state = generate_token(10)

    query = Query(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url=request_url, query=query, method=RequestMethod.GET, user=user,
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST
