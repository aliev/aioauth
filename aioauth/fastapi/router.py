from aioauth.config import Settings
from aioauth.server import AuthorizationServer
from fastapi import APIRouter, Request, Depends
from .utils import to_oauth2_request, to_fastapi_response
from aioauth.requests import Query
from .forms import TokenForm, TokenIntrospectForm


def get_oauth2_router(authorization_server: AuthorizationServer, settings: Settings):
    router = APIRouter()

    @router.post("/token")
    async def token(request: Request, form: TokenForm = Depends()):
        oauth2_request = await to_oauth2_request(request, settings)
        oauth2_response = await authorization_server.create_token_response(
            oauth2_request
        )
        return await to_fastapi_response(oauth2_response)

    @router.post("/token/introspect")
    async def token_introspect(request: Request, form: TokenIntrospectForm = Depends()):
        oauth2_request = await to_oauth2_request(request, settings)
        oauth2_response = (
            await authorization_server.create_token_introspection_response(
                oauth2_request
            )
        )
        return await to_fastapi_response(oauth2_response)

    @router.get("/authorize")
    async def authorize(request: Request, query: Query = Depends()):
        oauth2_request = await to_oauth2_request(request, settings)
        oauth2_response = await authorization_server.create_authorization_response(
            oauth2_request
        )
        return await to_fastapi_response(oauth2_response)

    return router
