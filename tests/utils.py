from dataclasses import asdict, replace
from http import HTTPStatus
from typing import Any, Callable, Dict, Union

from aioauth.collections import HTTPHeaderDict
from aioauth.constances import default_headers
from aioauth.requests import Post, Query, Request
from aioauth.responses import ErrorResponse, Response
from aioauth.types import ErrorType, RequestMethod

EMPTY_KEYS = {
    RequestMethod.GET: {
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Missing client_id parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Missing response_type parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Mismatching redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Code challenge required.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "nonce": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Nonce required for response_type id_token.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    RequestMethod.POST: {
        "grant_type": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Request is missing grant type.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Mismatching redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Missing code parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Missing refresh token parameter.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Code verifier required.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_CLIENT,
                    description="",
                )
            ),
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=HTTPHeaderDict({"www-authenticate": "Basic"}),
        ),
        "client_secret": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_CLIENT,
                    description="",
                )
            ),
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=HTTPHeaderDict({"www-authenticate": "Basic"}),
        ),
        "username": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid credentials given.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid credentials given.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
}

INVALID_KEYS = {
    RequestMethod.GET: {
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid client_id parameter value.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.UNSUPPORTED_RESPONSE_TYPE,
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge_method": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Transform algorithm not supported.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "scope": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_SCOPE,
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    RequestMethod.POST: {
        "grant_type": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.UNSUPPORTED_GRANT_TYPE,
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid redirect URI.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_GRANT,
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.MISMATCHING_STATE,
                    description="CSRF Warning! State not equal in request and response.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_GRANT,
                    description="",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_id": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid client_id parameter value.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_secret": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid client_id parameter value.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "username": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid credentials given.",
                )
            ),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=asdict(
                ErrorResponse(
                    error=ErrorType.INVALID_REQUEST,
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

        if request_.method == RequestMethod.POST:
            post = replace(request_.post, **{key: value})
            request_ = replace(request_, post=post)

        if request_.method == RequestMethod.GET:
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

    if request.method == RequestMethod.POST:
        query_dict = get_keys(request.post)

    if request.method == RequestMethod.GET:
        query_dict = get_keys(request.query)

    responses = EMPTY_KEYS[request.method]
    await check_query_values(request, responses, query_dict, endpoint_func, None)

    responses = INVALID_KEYS[request.method]
    await check_query_values(request, responses, query_dict, endpoint_func, "invalid")
