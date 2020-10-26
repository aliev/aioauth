from copy import deepcopy
from dataclasses import asdict
from http import HTTPStatus
from typing import Callable

from async_oauth2_provider.constances import default_headers
from async_oauth2_provider.requests import Request
from async_oauth2_provider.responses import ErrorResponse, Response
from async_oauth2_provider.types import ErrorType, RequestMethod

EMPTY_KEYS = {
    RequestMethod.GET: {
        "client_id": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Missing client_id parameter.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Missing response_type parameter.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Mismatching redirect URI.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST, description="Code challenge required.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    RequestMethod.POST: {
        "grant_type": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Request is missing grant type.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Mismatching redirect URI.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST, description="Missing code parameter.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Missing refresh token parameter.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST, description="Code verifier required.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "username": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT, description="Invalid credentials given.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT, description="Invalid credentials given.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
}

INVALID_KEYS = {
    RequestMethod.GET: {
        "client_id": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Invalid client_id parameter value.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=ErrorResponse(
                error=ErrorType.UNSUPPORTED_RESPONSE_TYPE, description="",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST, description="Invalid redirect URI.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge_method": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Transform algorithm not supported.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "scope": Response(
            content=ErrorResponse(error=ErrorType.INVALID_SCOPE, description="",),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    RequestMethod.POST: {
        "grant_type": Response(
            content=ErrorResponse(
                error=ErrorType.UNSUPPORTED_GRANT_TYPE, description="",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST, description="Invalid redirect URI.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=ErrorResponse(error=ErrorType.INVALID_GRANT, description="",),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=ErrorResponse(
                error=ErrorType.MISMATCHING_STATE,
                description="CSRF Warning! State not equal in request and response.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=ErrorResponse(error=ErrorType.INVALID_GRANT, description="",),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "username": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT, description="Invalid credentials given.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT, description="Invalid credentials given.",
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
}


def get_keys(query):
    return {key: value for key, value in asdict(query).items() if bool(value)}


async def check_query_keys(
    request: Request, endpoint_func: Callable,
):
    query_dict = {}

    if request.method == RequestMethod.POST:
        query_dict = get_keys(request.post)

    if request.method == RequestMethod.GET:
        query_dict = get_keys(request.query)

    responses = EMPTY_KEYS[request.method]
    keys = set(query_dict.keys()) & set(responses.keys())

    for key in keys:
        request_ = deepcopy(request)

        if request.method == RequestMethod.POST:
            setattr(request_.post, key, None)

        if request.method == RequestMethod.GET:
            setattr(request_.query, key, None)

        response_expected = responses[key]
        response_actual = await endpoint_func(request_)

        assert response_expected == response_actual

    responses = INVALID_KEYS[request.method]
    keys = set(query_dict.keys()) & set(responses.keys())

    for key in keys:
        request_ = deepcopy(request)

        if request.method == RequestMethod.POST:
            setattr(request_.post, key, "invalid")

        if request.method == RequestMethod.GET:
            setattr(request_.query, key, "invalid")

        response_expected = responses[key]
        response_actual = await endpoint_func(request_)

        assert response_expected == response_actual
