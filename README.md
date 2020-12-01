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

To interact with the database (create tokens, check authorization code, etc.), you need to inherit from the [BaseDB](src/aioauth/base/database.py) class and implement all its methods. This allows aioauth not to be tied to a specific database and gives the user choice of which database he wants to use. You can get additional documentation on all [BaseDB](src/aioauth/base/database.py) methods in the source code of this class.

```python
import json

from fastapi import APIRouter, Request, Response

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
    ...

router = APIRouter()
server = AuthorizationServer(db=DB())


@router.post("/token")
async def token(request: Request):
    oauth2_request: OAuth2Request = await to_oauth2_request(request)
    oauth2_response: OAuth2Response = await server.create_token_response(oauth2_request)

    return await to_fastapi_response(oauth2_response)


@router.get("/authorize")
async def authorize(request: Request):
    oauth2_request: OAuth2Request = await to_oauth2_request(request)
    oauth2_response: Response = await server.create_authorization_response(oauth2_request)

    return await to_fastapi_response(oauth2_response)


async def to_oauth2_request(request: Request) -> OAuth2Request:
    """Converts fastapi Request instance to OAuth2Request instance"""
    form = await request.form()

    post = dict(form)
    query_params = dict(request.query_params)
    method = request.method
    headers = CaseInsensitiveDict(**request.headers)
    url = str(request.url)
    user = request.user

    # NOTE: Redefinition of the default settings
    # INSECURE_TRANSPORT must be enabled for local development only!
    settings=Settings(
        INSECURE_TRANSPORT=True,
    ),

    return OAuth2Request(
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
