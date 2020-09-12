from async_oauth2_provider.requests import Request as OAuth2Request
from async_oauth2_provider.responses import Response as OAuth2Response
from fastapi import Request, Response


async def to_oauth2_request(request: Request) -> OAuth2Request:
    """ Converts fastapi Request instance to OAuth2Request instance

    :param request: fastapi Request instance
    :type request: Request
    :return: returns OAuth2Request instance
    :rtype: OAuth2Request
    """
    form = await request.form()

    post = dict(form)
    query_params = dict(request.query_params)
    method = request.method
    headers = dict(request.headers)
    url = str(request.url)

    return OAuth2Request(
        post=post, query=query_params, method=method, headers=headers, url=url
    )


async def to_fastapi_response(oauth2_response: OAuth2Response) -> Response:
    """ Converts OAuth2Response instance to fastapi Response instance

    :param oauth2_response: OAuth2Response instance
    :type oauth2_response: OAuth2Response
    :return: returns fastapi Response instance
    :rtype: Response
    """
    content = oauth2_response.content.json()
    headers = oauth2_response.headers
    status_code = oauth2_response.status_code.value

    return Response(content=content, headers=headers, status_code=status_code)
