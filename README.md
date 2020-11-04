## Asynchronous OAuth 2.0 framework for Python 3

`aioauth` implements [OAuth 2.0 protocol](https://tools.ietf.org/html/rfc6749) and can be used in asynchronous frameworks like [FastAPI / Starlette](https://github.com/tiangolo/fastapi), [aiohttp](https://github.com/aio-libs/aiohttp). It can work with any databases like `MongoDB`, `PostgreSQL`, `MySQL` and ORMs like [gino](https://python-gino.org/), [sqlalchemy](https://www.sqlalchemy.org/) or [databases](https://pypi.org/project/databases/) over simple [BaseDB](src/aioauth/db.py) interface.

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

## Settings and defaults

| Setting                                | Default value | Description                                                                                                         |
| -------------------------------------- | ------------- | --------------------=---------------------------------------------------------------------------------------------- |
| AIOAUTH_TOKEN_EXPIRES_IN               | 86400         | Access token lifetime.                                                                                              |
| AIOAUTH_AUTHORIZATION_CODE_EXPIRES_IN  | 300           | Authorization code lifetime.                                                                                        |
| AIOAUTH_INSECURE_TRANSPORT             | False         | Allow connections over SSL only. When this option is disabled server will raise "HTTP method is not allowed" error. |
