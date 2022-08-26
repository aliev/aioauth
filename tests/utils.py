from dataclasses import asdict, replace
from http import HTTPStatus
from typing import Any, Callable, Dict, Union

from aioauth.collections import HTTPHeaderDict
from aioauth.constances import default_headers
from aioauth.requests import Post, Query, Request
from aioauth.responses import ErrorResponse, Response

EMPTY_KEYS = {
    "GET": {
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Missing client_id parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Missing response_type parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Mismatching redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Code challenge required.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "nonce": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Nonce required for response_type id_token.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    "POST": {
        "grant_type": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Request is missing grant type.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Mismatching redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Missing code parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Missing refresh token parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Code verifier required.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_client",
                    description="",
                )
            ),
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=HTTPHeaderDict({"www-authenticate": "Basic"}),
        ),
        "client_secret": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_client",
                    description="",
                )
            ),
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=HTTPHeaderDict({"www-authenticate": "Basic"}),
        ),
        "username": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid credentials given.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid credentials given.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
}

INVALID_KEYS = {
    "GET": {
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid client_id parameter value.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=asdict(
                ErrorResponse(
                    error="unsupported_response_type",
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge_method": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Transform algorithm not supported.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "scope": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_scope",
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    "POST": {
        "grant_type": Response(
            content=asdict(
                ErrorResponse(
                    error="unsupported_grant_type",
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_grant",
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=asdict(
                ErrorResponse(
                    error="mismatching_state",
                    description="CSRF Warning! State not equal in request and response.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_grant",
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid client_id parameter value.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_secret": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid client_id parameter value.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "username": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid credentials given.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=asdict(
                ErrorResponse(
                    error="invalid_request",
                    description="Invalid credentials given.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
}


def get_keys(query: Union[Query, Post]) -> Dict[str, Any]:
    """Converts dataclass object to dict and returns dict without empty values"""
    return {key: value for key, value in asdict(query).items() if bool(value)}


async def check_query_values(
    request: Request, responses, query_dict: Dict, endpoint_func, value
):
    keys = set(query_dict.keys()) & set(responses.keys())

    for key in keys:
        request_ = request

        if request_.method == "POST":
            post = replace(request_.post, **{key: value})
            request_ = replace(request_, post=post)

        if request_.method == "GET":
            query = replace(request_.query, **{key: value})
            request_ = replace(request_, query=query)

        response_expected = responses[key]
        response_actual = await endpoint_func(request_)

        assert (
            response_expected == response_actual
        ), f"{response_expected} != {response_actual}"


async def check_request_validators(
    request: Request,
    endpoint_func: Callable,
):
    query_dict = {}

    if request.method == "POST":
        query_dict = get_keys(request.post)

    if request.method == "GET":
        query_dict = get_keys(request.query)

    responses = EMPTY_KEYS[request.method]
    await check_query_values(request, responses, query_dict, endpoint_func, None)

    responses = INVALID_KEYS[request.method]
    await check_query_values(request, responses, query_dict, endpoint_func, "invalid")
