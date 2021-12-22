FastAPI
=======

.. code-block:: python

    from aioauth_fastapi.router import get_oauth2_router
    from aioauth.storage import BaseStorage
    from aioauth.config import Settings
    from aioauth.server import AuthorizationServer
    from fastapi import FastAPI

    app = FastAPI()

    class Storage(BaseStorage):
        """
        Storage methods must be implemented here.
        """

    storage = Storage()
    authorization_server = AuthorizationServer(storage)

    # NOTE: Redefinition of the default aioauth settings
    # INSECURE_TRANSPORT must be enabled for local development only!
    settings = Settings(
        INSECURE_TRANSPORT=True,
    )

    # Include FastAPI router with oauth2 endpoints.
    app.include_router(
        get_oauth2_router(authorization_server, settings),
        prefix="/oauth2",
        tags=["oauth2"],
    )
