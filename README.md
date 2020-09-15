## `async-oauth2-provider` - asynchronous [OAuth 2.0](https://tools.ietf.org/html/rfc6749) framework for Python 3

## Why this project exists?

There are few great OAuth frameworks like [oauthlib](https://github.com/oauthlib/oauthlib) and [authlib](https://github.com/lepture/authlib) but they do not support asyncio and rewriting these libraries to asyncio is a big challenge. `async-oauth2-provider` implements [OAuth 2.0](https://tools.ietf.org/html/rfc6749) and can be used in [FastAPI / Starlette](https://github.com/aliev/async-oauth2-provider/tree/master/examples), aiohttp or any other asyncronous frameworks.

## Features

- [x] Can work with any databases (`MongoDB`, `PostgreSQL`, `MySQL` etc.) and ORMs ([gino](https://python-gino.org/), [sqlalchemy](https://www.sqlalchemy.org/), [databases](https://pypi.org/project/databases/)) over simple [DBBase](https://github.com/aliev/async-oauth2-provider/blob/master/src/async_oauth2_provider/db.py) interface.
- [x] Can be easily integrated to any asynchronous frameworks over simple API.

This repository also contains integration examples with [FastAPI / Starlette](https://github.com/aliev/async-oauth2-provider/tree/master/examples) and [aiohttp](https://github.com/aliev/async-oauth2-provider/tree/master/examples).

## Installation

```
python -m pip install async-oauth2-provider
```

## Supported RFCs

- [x] [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [ ] [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [ ] [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)
- [ ] [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)

## Settings

| Setting                               | Default value | Description                                                                                                         |
| ------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------- |
| OAUTH2_TOKEN_EXPIRES_IN               | 86400         | Access token lifetime. Default value in seconds.                                                                    |
| OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN  | 300           | Authorization code lifetime. Default value in seconds.                                                              |
| OAUTH2_INSECURE_TRANSPORT             | False         | Allow connections over SSL only. When this option is disabled server will raise "HTTP method is not allowed" error. |
