"""
Bare Minimum Example of FastAPI Implementation of AioAuth

(Supports AuthCode/Token/RefreshToken ONLY)
"""

import json
import html
from http import HTTPStatus
from typing import Optional, cast

from fastapi import FastAPI, Form, Request, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi_extras.session import SessionMiddleware
from sqlmodel.ext.asyncio.session import AsyncSession

from aioauth.collections import HTTPHeaderDict
from aioauth.requests import Post, Query
from aioauth.requests import Request as OAuthRequest
from aioauth.responses import Response as OAuthResponse
from aioauth.types import RequestMethod

from shared import AuthServer, BackendStore, engine, settings, try_login, lifespan

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
async def login(request: Request, error: Optional[str] = None):
    """
    barebones login page, redirects to approval after completion
    """
    if "oauth" not in request.session and error is None:
        error = "Cannot Login without OAuth Session"
    error = html.escape(error) if error else ""  # never trust user-input
    content = f"""
<html>
    <body>
        <h3>Login Form</h3>
        <p style="color: red">{error}</p>
        <form method="POST">
            <table>
                <tr>
                    <td><label for="un">Username</label></td>
                    <td><input id="un" name="username" type="text" value="admin" /></td>
                </tr>
                <tr>
                    <td><label for="pw">Password</label></td>
                    <td><input id="pw" name="password" type="password" value="admin" /></td>
                </tr>
                <tr>
                    <td></td>
                    <td><button type="submit" style="width: 100%">Login</button></td>
                </tr>
            </table>
        </form>
    </body>
</html>
    """
    return HTMLResponse(content, status_code=400 if error else 200)


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(),
    password: str = Form(),
):
    """
    login form submission handler, redirects to approval on success
    """
    user = await try_login(username, password)
    if user is None:
        return await login(request, error="Invalid Username or Password")
    request.session["user"] = user
    redirect = request.url_for("approve")
    return RedirectResponse(redirect, status_code=303)
    # # sign in user


@app.get("/approve")
async def approve(request: Request):
    """
    barebones approval page, finalizes response after completion
    """
    if "user" not in request.session:
        redirect = request.url_for("login")
        return RedirectResponse(redirect)
    oauthreq: OAuthRequest = request.session["oauth"]
    content = f"""
<html>
    <body>
        <h3>{oauthreq.query.client_id} would like permissions.</h3>
        <form method="POST">
            <button name="approval" value="0" type="submit">Deny</button>
            <button name="approval" value="1" type="submit">Approve</button>
        </form>
    </body>
</html>
    """
    return HTMLResponse(content)


@app.post("/approve")
async def approve_submit(
    request: Request,
    approval: int = Form(),
    oauth: AuthServer = Depends(get_auth_server),
):
    """ """
    oauthreq = request.session["oauth"]
    oauthreq.user = request.session["user"]
    if not approval:
        # TODO: generate `permission_denied` response
        return await approve(request)
    # process authorize request
    response = await oauth.create_authorization_response(oauthreq)
    return to_response(response)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app)
