from http import HTTPStatus
from typing import Any, Callable, Dict, Union

from aioauth.constances import default_headers
from aioauth.requests import Post, Query, Request
from aioauth.responses import ErrorResponse, Response
from aioauth.structures import CaseInsensitiveDict
from aioauth.types import ErrorType, RequestMethod

EMPTY_KEYS = {
    RequestMethod.GET: {
        "client_id": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Missing client_id parameter.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Missing response_type parameter.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Mismatching redirect URI.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Code challenge required.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "nonce": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Nonce required for response_type id_token.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    RequestMethod.POST: {
        "grant_type": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Request is missing grant type.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Mismatching redirect URI.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Missing code parameter.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Missing refresh token parameter.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Code verifier required.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_id": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_CLIENT,
                description="",
            )._asdict(),
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=CaseInsensitiveDict({"www-authenticate": "Basic"}),
        ),
        "client_secret": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_CLIENT,
                description="",
            )._asdict(),
            status_code=HTTPStatus.UNAUTHORIZED,
            headers=CaseInsensitiveDict({"www-authenticate": "Basic"}),
        ),
        "username": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT,
                description="Invalid credentials given.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT,
                description="Invalid credentials given.",
            )._asdict(),
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
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "response_type": Response(
            content=ErrorResponse(
                error=ErrorType.UNSUPPORTED_RESPONSE_TYPE,
                description="",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Invalid redirect URI.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_challenge_method": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Transform algorithm not supported.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "scope": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_SCOPE,
                description="",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
    RequestMethod.POST: {
        "grant_type": Response(
            content=ErrorResponse(
                error=ErrorType.UNSUPPORTED_GRANT_TYPE,
                description="",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "redirect_uri": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Invalid redirect URI.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT,
                description="",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "code_verifier": Response(
            content=ErrorResponse(
                error=ErrorType.MISMATCHING_STATE,
                description="CSRF Warning! State not equal in request and response.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "refresh_token": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT,
                description="",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_id": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Invalid client_id parameter value.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "client_secret": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_REQUEST,
                description="Invalid client_id parameter value.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "username": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT,
                description="Invalid credentials given.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
        "password": Response(
            content=ErrorResponse(
                error=ErrorType.INVALID_GRANT,
                description="Invalid credentials given.",
            )._asdict(),
            status_code=HTTPStatus.BAD_REQUEST,
            headers=default_headers,
        ),
    },
}


def get_keys(query: Union[Query, Post]) -> Dict[str, Any]:
    """Converts dataclass object to dict and returns dict without empty values"""
    return {key: value for key, value in query.__dict__.items() if bool(value)}


def set_values(model, values):
    """Sets NamedTuple instance value and returns new NamedTuple"""
    return model.__class__(**{**model.__dict__, **values})


async def check_query_values(
    request: Request, responses, query_dict: Dict, endpoint_func, value
):
    keys = set(query_dict.keys()) & set(responses.keys())

    for key in keys:
        request_ = request

        if request_.method == RequestMethod.POST:
            post = set_values(request_.post, {key: value})
            request_ = set_values(request_, {"post": post})

        if request_.method == RequestMethod.GET:
            query = set_values(request_.query, {key: value})
            request_ = set_values(request_, {"query": query})

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
