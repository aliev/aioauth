## Asynchronous OAuth 2.0 framework for Python 3

`aioauth` implements [OAuth 2.0 protocol](https://tools.ietf.org/html/rfc6749) and can be used in asynchronous frameworks like [FastAPI / Starlette](https://github.com/tiangolo/fastapi), [aiohttp](https://github.com/aio-libs/aiohttp). It can work with any databases like `MongoDB`, `PostgreSQL`, `MySQL` and ORMs like [gino](https://python-gino.org/), [sqlalchemy](https://www.sqlalchemy.org/) or [databases](https://pypi.org/project/databases/) over simple [BaseDB](src/aioauth/base/database.py) interface.

## Why this project exists?

There are few great OAuth frameworks for Python like [oauthlib](https://github.com/oauthlib/oauthlib) and [authlib](https://github.com/lepture/authlib), but they do not support asyncio and rewriting these libraries to asyncio is a significant challenge (see issues [here](https://github.com/lepture/authlib/issues/63) and [here](https://github.com/oauthlib/oauthlib/issues/415)).

## Supported RFCs

- [x] [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [X] [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [X] [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)

## Installation

```
python -m pip install aioauth
```

## FastAPI Example
```python
import json

from fastapi import FastAPI, Request, Response

from aioauth.server import AuthorizationServer
from aioauth.types import RequestMethod
from aioauth.config import Settings
from aioauth.base.database import BaseDB
from aioauth.requests import (
    Query,
    Post,
    Request as OAuth2Request,
)
from aioauth.responses import Response as OAuth2Response
from aioauth.structures import CaseInsensitiveDict


class DB(BaseDB):
    """Class for interacting with the database. Used by `AuthorizationServer`.

    Here you need to override the methods that are responsible for creating tokens,
    creating authorization code, getting a client from the database, etc.
    """

    async def create_token(self, *args, **kwargs) -> Token:
        """Create token code in db
        """
        token = await super().create_token(*args, **kwargs)
        # NOTE: Save data from token to db here.
        return token

    async def create_authorization_code(self, *args, **kwargs) -> AuthorizationCode:
        """Create authorization code in db
        """
        authorization_code = await super().create_authorization_code(*args, **kwargs)
        # NOTE: Save data from authorization_code to db here.
        return authorization_code

    async def get_token(self, *args, **kwargs) -> Optional[Token]:
        """Get token from the database by provided request from user.

        Returns:
            Token: if token exists in db.
            None: if no token in db.
        """
        token_record = ...

        if token_record is not None:
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

        if client_record is not None:
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
    response_content = oauth2_response.content._asdict() if oauth2_response.content is not None else {}
    headers = dict(oauth2_response.headers)
    status_code = oauth2_response.status_code
    content = json.dumps(response_content)

    return Response(content=content, headers=headers, status_code=status_code)
```

## Settings and defaults

| Setting                                | Default value | Description                                                                                                         |
| -------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------- |
|         TOKEN_EXPIRES_IN               | 86400         | Access token lifetime.                                                                                              |
|         AUTHORIZATION_CODE_EXPIRES_IN  | 300           | Authorization code lifetime.                                                                                        |
|         INSECURE_TRANSPORT             | False         | Allow connections over SSL only. When this option is disabled server will raise "HTTP method is not allowed" error. |


## Contributing

All contributions are welcome – especially:

- documentation,
- bug reports and issues,
- code contributions.

### Code

If you'd like to actively develop or help maintain this project then there are existing tests against which you can test the library with. Typically, this looks like

- `git clone git@github.com:aliev/aioauth.git`
- `cd aioauth`
- `python -mvenv env`
- `source env/bin/activate`
- `make dev-install`

`make dev-install` will also install all the required packages that will allow you to adhere to the code styling guide of `aioauth`.

Basically we use the `black` and `flake8` packages for code formatting, `pre-commit` package will check the code formatting before your first commit is made.

To automatically correct the formatting you can run the command inside the repository root:

```
black .
```

Running tests:

```
make test
```

the output result will also show the current coverage, please make sure the coverage is not below `99%`
