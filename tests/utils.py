from base64 import b64encode
from dataclasses import asdict
from http import HTTPStatus
from typing import Dict, Optional

from async_oauth2_provider.constances import default_headers
from async_oauth2_provider.requests import Post, Query, Request
from async_oauth2_provider.responses import ErrorResponse, Response
from async_oauth2_provider.structures import CaseInsensitiveDict
from async_oauth2_provider.types import ErrorType, RequestMethod


def set_authorization_headers(
    username: str, password: str, headers: Optional[CaseInsensitiveDict] = None
) -> CaseInsensitiveDict:

    if headers is None:
        headers = CaseInsensitiveDict()

    authorization = b64encode(f"{username}:{password}".encode("ascii"))
    return CaseInsensitiveDict(
        **headers, Authorization=f"basic {authorization.decode()}"
    )


def for_emptry_responses():
    expected_responses = {
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
                    error=ErrorType.INVALID_REQUEST,
                    description="Code challenge required.",
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
                    error=ErrorType.INVALID_REQUEST,
                    description="Missing code parameter.",
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
                    error=ErrorType.INVALID_REQUEST,
                    description="Code verifier required.",
                ),
                status_code=HTTPStatus.BAD_REQUEST,
                headers=default_headers,
            ),
            "username": Response(
                content=ErrorResponse(
                    error=ErrorType.INVALID_GRANT,
                    description="Invalid credentials given.",
                ),
                status_code=HTTPStatus.BAD_REQUEST,
                headers=default_headers,
            ),
            "password": Response(
                content=ErrorResponse(
                    error=ErrorType.INVALID_GRANT,
                    description="Invalid credentials given.",
                ),
                status_code=HTTPStatus.BAD_REQUEST,
                headers=default_headers,
            ),
        },
    }

    return expected_responses


def for_invalid_responses():
    expected_responses = {
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
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid redirect URI.",
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
                    error=ErrorType.INVALID_REQUEST,
                    description="Invalid redirect URI.",
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
                    error=ErrorType.INVALID_GRANT,
                    description="Invalid credentials given.",
                ),
                status_code=HTTPStatus.BAD_REQUEST,
                headers=default_headers,
            ),
            "password": Response(
                content=ErrorResponse(
                    error=ErrorType.INVALID_GRANT,
                    description="Invalid credentials given.",
                ),
                status_code=HTTPStatus.BAD_REQUEST,
                headers=default_headers,
            ),
        },
    }
    return expected_responses


async def check_params(request_params: Dict, endpoint_func):
    params = {}
    request_method = request_params["method"]

    if request_method == RequestMethod.GET:
        params = asdict(request_params["query"])

    if request_method == RequestMethod.POST:
        params = asdict(request_params["post"])

    empty_responses = for_emptry_responses()

    c = {key: value for key, value in params.items() if bool(value)}

    keys = set(empty_responses[request_method].keys()) & set(c.keys())

    for key in keys:
        response_expected = empty_responses[request_method][key]
        request = None

        if request_method == RequestMethod.GET:
            request = Request(
                **{**request_params, "query": Query(**{**params, key: None})}
            )

        if request_method == RequestMethod.POST:
            request = Request(
                **{**request_params, "post": Post(**{**params, key: None})}
            )

        response = await endpoint_func(request)
        assert response_expected == response

    invalid_responses = for_invalid_responses()

    c = {key: value for key, value in params.items() if bool(value)}

    keys = set(invalid_responses[request_method].keys()) & set(c.keys())

    for key in keys:
        response_expected = invalid_responses[request_method][key]
        request = None

        if request_method == RequestMethod.GET:
            request = Request(
                **{**request_params, "query": Query(**{**params, key: "invalid"})}
            )

        if request_method == RequestMethod.POST:
            request = Request(
                **{**request_params, "post": Post(**{**params, key: "invalid"})}
            )

        response = await endpoint_func(request)
        assert response_expected == response
