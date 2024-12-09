"""
Bare Minimum Example of FastAPI Implementation of AioAuth

(Supports AuthCode/Token/RefreshToken ONLY)
"""

import json
from http import HTTPStatus
from typing import cast

from fastapi import FastAPI, Request, Depends, Response
from fastapi.responses import RedirectResponse
from fastapi_extras.session import SessionMiddleware
from sqlmodel.ext.asyncio.session import AsyncSession

from aioauth.collections import HTTPHeaderDict
from aioauth.requests import Post, Query
from aioauth.requests import Request as OAuthRequest
from aioauth.responses import Response as OAuthResponse
from aioauth.types import RequestMethod

from shared import AuthServer, BackendStore, engine, settings, auto_login, lifespan

app = FastAPI(lifespan=lifespan)

app.add_middleware(SessionMiddleware)


async def get_auth_server() -> AuthServer:
    """
    initialize oauth authorization server
    """
    session = AsyncSession(engine)
    storage = BackendStore(session)
    return AuthServer(storage)


async def to_request(request: Request) -> OAuthRequest:
    """
    convert fastapi request to aioauth oauth2 request
    """
    user = request.session.get("user", None)
    form = await request.form()
    return OAuthRequest(
        headers=HTTPHeaderDict(**request.headers),
        method=cast(RequestMethod, request.method),
        post=Post(**form),  # type: ignore
        query=Query(**request.query_params),  # type: ignore
        settings=settings,
        url=str(request.url),
        user=user,
    )


def to_response(response: OAuthResponse) -> Response:
    """
    convert aioauth oauth2 response into fastapi response
    """
    return Response(
        content=json.dumps(response.content),
        headers=dict(response.headers),
        status_code=response.status_code,
    )


@app.get("/oauth/authorize")
async def authorize(
    request: Request, oauth: AuthServer = Depends(get_auth_server)
) -> Response:
    """
    oauth2 authorization endpoint using aioauth
    """
    oauthreq = await to_request(request)
    response = await oauth.create_authorization_response(oauthreq)
    if response.status_code == HTTPStatus.UNAUTHORIZED:
        request.session["oauth"] = oauthreq
        return RedirectResponse("/login")
    return to_response(response)


@app.post("/oauth/tokenize")
async def tokenize(
    request: Request,
    oauth: AuthServer = Depends(get_auth_server),
):
    """
    oauth2 tokenization endpoint using aioauth
    """
    oauthreq = await to_request(request)
    response = await oauth.create_token_response(oauthreq)
    return to_response(response)


@app.get("/login")
async def login(request: Request, oauth: AuthServer = Depends(get_auth_server)):
    """
    barebones "login" page, redirected to when authorize is called before login
    """
    # sign in user
    oauthreq = request.session["oauth"]
    oauthreq.user = await auto_login()
    # process authorize request
    response = await oauth.create_authorization_response(oauthreq)
    return to_response(response)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app)
