"""
Bare Minimum Example of FastAPI Implementation of AioAuth

(Supports AuthCode/Token/RefreshToken ONLY)
"""

import json
import html
import logging
from typing import Optional, cast

from fastapi import FastAPI, Form, Request, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi_extras.session import SessionMiddleware
from sqlmodel.ext.asyncio.session import AsyncSession

from aioauth.collections import HTTPHeaderDict
from aioauth.errors import AccessDeniedError, OAuth2Error
from aioauth.requests import Post, Query
from aioauth.requests import Request as OAuthRequest
from aioauth.responses import Response as OAuthResponse
from aioauth.server import AuthorizationState as OAuthState
from aioauth.types import RequestMethod
from aioauth.utils import build_error_response

from shared import AuthServer, BackendStore, engine, settings, try_login, lifespan

app = FastAPI(lifespan=lifespan)

app.add_middleware(SessionMiddleware)


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s,%(msecs)d %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)


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
        extra={"user": user},
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
    # validate initial request and return error response (if supplied)
    oauthreq = await to_request(request)

    try:
        state = await oauth.validate_authorization_request(oauthreq)
    except OAuth2Error as exc:
        response = build_error_response(exc=exc, request=oauthreq)
        return to_response(response)

    # redirect to login if user information is missing
    user = request.session.get("user", None)
    request.session["oauth"] = state
    if user is None:
        return RedirectResponse("/login")
    # otherwise redirect to approval
    return RedirectResponse("/approve")


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


@app.get("/approve")
async def approve(request: Request):
    """
    barebones approval page, finalizes response after completion
    """
    if "user" not in request.session:
        redirect = request.url_for("login")
        return RedirectResponse(redirect)
    oauth: Optional[OAuthState] = request.session.get("oauth", None)
    if oauth:
        content = f"""
        <html>
            <body>
                <h3>{oauth.request.query.client_id} would like permissions.</h3>
                <form method="POST">
                    <button name="approval" value="0" type="submit">Deny</button>
                    <button name="approval" value="1" type="submit">Approve</button>
                </form>
            </body>
        </html>
        """
    else:
        content = f"""
        <html>
            <body>
                <h3>Hello, {request.session['user'].username}.</h3>
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
    """
    scope approval form submission handler
    """
    if "oauth" not in request.session:
        return await approve(request)
    state: OAuthState = request.session["oauth"]
    state.request.extra["user"] = request.session["user"]
    # remove oauth-session once approval/denial is given
    request.session.pop("oauth", None)
    if not approval:
        # generate error response on deny
        error = AccessDeniedError(state.request, "User rejected scopes")
        response = build_error_response(error, state.request, skip_redirect_on_exc=())
    else:
        # process authorize request
        response = await oauth.finalize_authorization_response(state)
    return to_response(response)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app)
