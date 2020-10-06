from http import HTTPStatus
from typing import Dict

import pytest
from async_oauth2_provider.endpoints import OAuth2Endpoint
from async_oauth2_provider.requests import Query, Request
from async_oauth2_provider.types import CodeChallengeMethod, RequestMethod, ResponseType
from async_oauth2_provider.utils import generate_token
from tests.conftest import Defaults


@pytest.mark.asyncio
async def test_anonymous_user(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )
    request = Request(url="https://localhost", query=query, method=RequestMethod.GET,)
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_invalid_response_type(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)

    query = Query(
        client_id=defaults.client_id,
        response_type="Invalid",  # type: ignore
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    query = Query(
        client_id=defaults.client_id,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_empty_client_id(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)

    query = Query(
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_empty_redirect_uri(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)

    query = Query(
        client_id=defaults.client_id,
        response_type=ResponseType.TYPE_CODE,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_invalid_client_id(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)

    query = Query(
        client_id="invalid",
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url="https://localhost", query=query, method=RequestMethod.GET, user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_insecure_transport(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)

    query = Query(
        client_id="invalid",
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url="http://localhost", query=query, method=RequestMethod.GET, user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.asyncio
async def test_allowed_method(
    endpoint: OAuth2Endpoint, defaults: Defaults, storage: Dict
):
    code_challenge = generate_token(128)

    query = Query(
        client_id="invalid",
        response_type=ResponseType.TYPE_CODE,
        redirect_uri=defaults.redirect_uri,
        scope=defaults.scope,
        state=generate_token(10),
        code_challenge_method=CodeChallengeMethod.PLAIN,
        code_challenge=code_challenge,
    )

    request = Request(
        url="https://localhost",
        query=query,
        method=RequestMethod.POST,
        user="username",
    )
    response = await endpoint.create_authorization_code_response(request)
    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED
    assert RequestMethod.GET in response.headers["allow"]
