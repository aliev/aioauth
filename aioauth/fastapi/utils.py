"""
.. code-block:: python

    from aioauth.fastapi import utils

Core utils for integration with FastAPI

----
"""

import json

from fastapi import Request, Response

from aioauth.collections import HTTPHeaderDict
from aioauth.config import Settings
from aioauth.requests import Post, Query
from aioauth.requests import Request as OAuth2Request
from aioauth.responses import Response as OAuth2Response
from aioauth.types import RequestMethod


async def to_oauth2_request(
    request: Request, settings: Settings = Settings()
) -> OAuth2Request:
    """Converts :py:class:`fastapi.Request` instance to :py:class:`aioauth.requests.Request` instance"""
    form = await request.form()

    post = dict(form)
    query_params = dict(request.query_params)
    method = request.method
    headers = HTTPHeaderDict(**request.headers)
    url = str(request.url)

    user = None

    if request.user.is_authenticated:
        user = request.user

    return OAuth2Request(
        settings=settings,
        method=RequestMethod[method],
        headers=headers,
        post=Post(**post),
        query=Query(**query_params),
        url=url,
        user=user,
    )


async def to_fastapi_response(oauth2_response: OAuth2Response) -> Response:
    """Converts :py:class:`aioauth.responses.Response` instance to :py:class:`fastapi.Response` instance"""
    response_content = oauth2_response.content
    headers = dict(oauth2_response.headers)
    status_code = oauth2_response.status_code
    content = json.dumps(response_content)

    return Response(content=content, headers=headers, status_code=status_code)
