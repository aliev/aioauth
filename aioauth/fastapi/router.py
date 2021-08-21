"""
.. code-block:: python

    from aioauth.fastapi import router

FastAPI routing of oauth2.

Usage example

.. code-block:: python

    from aioauth.fastapi.router import get_oauth2_router
    from aioauth.storage import BaseStorage
    from aioauth.config import Settings
    from aioauth.server import AuthorizationServer
    from fastapi import FastAPI

    app = FastAPI()

    class Storage(BaseStorage):
        '''
        Storage methods must be implemented here.
        '''

    # NOTE: Redefinition of the default aioauth settings
    # INSECURE_TRANSPORT must be enabled for local development only!
    settings = Settings(
        INSECURE_TRANSPORT=True,
    )

    storage = Storage()
    authorization_server = AuthorizationServer(storage)

    # Include FastAPI router with oauth2 endpoints.
    app.include_router(
        get_oauth2_router(authorization_server, settings),
        prefix="/oauth2",
        tags=["oauth2"],
    )

----
"""

from aioauth.config import Settings
from aioauth.server import AuthorizationServer
from fastapi import APIRouter, Request, Depends
from .utils import to_oauth2_request, to_fastapi_response
from aioauth.requests import Query
from .forms import TokenForm, TokenIntrospectForm


def get_oauth2_router(
    authorization_server: AuthorizationServer, settings: Settings = Settings()
) -> APIRouter:
    """Function will create FastAPI router with the following oauth2 endpoints:

        * POST /token
            * Endpoint creates token response by :py:meth:`aioauth.server.AuthorizationServer.create_token_response`
        * POST `/token/introspect`
            * Endpoint creates token introspection by :py:meth:`aioauth.server.AuthorizationServer.create_token_introspection_response`
        * GET `/authorize`
            * Endpoint creates authorization response by :py:meth:`aioauth.server.AuthorizationServer.create_authorization_response`

    Returns:
        :py:class:`fastapi.APIRouter`.
    """
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
