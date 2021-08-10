FastAPI
=======

.. code-block:: python

    import json

    from fastapi import FastAPI, Request, Response

    from aioauth.server import AuthorizationServer
    from aioauth.types import RequestMethod
    from aioauth.config import Settings
    from aioauth.storage import BaseStorage
    from aioauth.requests import (
        Query,
        Post,
        Request as OAuth2Request,
    )
    from aioauth.responses import Response as OAuth2Response
    from aioauth.structures import CaseInsensitiveDict


    class DB(BaseStorage):
        """Class for interacting with the database. Used by `AuthorizationServer`.

        Here you need to override the methods that are responsible for creating tokens,
        creating authorization code, getting a client from the database, etc.
        """

        async def save_token(self, token: Token):
            """Store ALL fields of the Token namedtuple in a storage"""
            ...

        async def save_authorization_code(self, authorization_code: AuthorizationCode):
            """Store ALL fields of the AuthorizationCode namedtuple in a storage"""
            ...

        async def get_token(self, *args, **kwargs) -> Optional[Token]:
            """Get token from the database by provided request from user.

            Returns:
                Token: if token exists in storage.
                None: if no token in storage.
            """
            token_record = ...

            if not token_record:
                return None

            return Token(
                access_token=token_record.access_token,
                refresh_token=token_record.refresh_token,
                scope=token_record.scope,
                issued_at=token_record.issued_at,
                expires_in=token_record.expires_in,
                client_id=token_record.client_id,
                token_type=token_record.token_type,
                revoked=token_record.revoked
            )

        async def get_client(self, *args, **kwargs) -> Optional[Client]:
            """Get client record from the database by provided request from user.

            Returns:
                `Client` instance if client exists in db.
                `None` if no client in db.
            """

            client_record = ...

            if not client_record:
                return None

            return Client(
                client_id=client_record.client_id,
                client_secret=client_record.client_secret,
                grant_types=client_record.grant_types,
                response_types=client_record.response_types,
                redirect_uris=client_record.redirect_uris,
                scope=client_record.scope
            )

        async def revoke_token(self, request: Request, token: str) -> None:
            """Revokes an existing token. The `revoked`

            Flag of the Token must be set to True
            """
            token_record = ...
            token_record.revoked = True
            token_record.save()

        async def get_authorization_code(self, *args, **kwargs) -> Optional[AuthorizationCode]:
            ...

        async def delete_authorization_code(self, *args, **kwargs) -> None:
            ...

        async def authenticate(self, *args, **kwargs) -> bool:
            ...

    app = FastAPI()
    server = AuthorizationServer(db=DB())

    # NOTE: Redefinition of the default aioauth settings
    # INSECURE_TRANSPORT must be enabled for local development only!
    settings = Settings(
        INSECURE_TRANSPORT=True,
    )


    @app.post("/token")
    async def token(request: Request) -> Response:
        """Endpoint to obtain an access and/or ID token by presenting an authorization grant or refresh token.

        See Section 4.1.3: https://tools.ietf.org/html/rfc6749#section-4.1.3
        """
        oauth2_request: OAuth2Request = await to_oauth2_request(request)
        oauth2_response: OAuth2Response = await server.create_token_response(oauth2_request)

        return await to_fastapi_response(oauth2_response)


    @app.get("/authorize")
    async def authorize(request: Request) -> Response:
        """Endpoint to interact with the resource owner and obtain an authorization grant.

        See Section 4.1.1: https://tools.ietf.org/html/rfc6749#section-4.1.1
        """
        oauth2_request: OAuth2Request = await to_oauth2_request(request)
        oauth2_response: OAuth2Response = await server.create_authorization_response(oauth2_request)

        return await to_fastapi_response(oauth2_response)


    @app.get("/introspect")
    async def introspect(request: Request) -> Response:
        """Endpoint returns information about a token.

        See Section 2.1: https://tools.ietf.org/html/rfc7662#section-2.1
        """
        oauth2_request: OAuth2Request = await to_oauth2_request(request)
        oauth2_response: OAuth2Response = await server.create_token_introspection_response(oauth2_request)

        return await to_fastapi_response(oauth2_response)


    async def to_oauth2_request(request: Request) -> OAuth2Request:
        """Converts fastapi Request instance to OAuth2Request instance"""
        form = await request.form()

        post = dict(form)
        query_params = dict(request.query_params)
        method = request.method
        headers = CaseInsensitiveDict(**request.headers)
        url = str(request.url)

        # NOTE: AuthenticationMiddleware must be installed
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
        """Converts OAuth2Response instance to fastapi Response instance"""
        response_content = oauth2_response.content
        headers = dict(oauth2_response.headers)
        status_code = oauth2_response.status_code
        content = json.dumps(response_content)

        return Response(content=content, headers=headers, status_code=status_code)
