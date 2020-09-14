## Why this project exists?

There are few great existing oauth provider libraries like [oauthlib](https://github.com/oauthlib/oauthlib) and [authlib](https://github.com/lepture/authlib) but they do not support asyncio and rewriting these libraries to asyncio is a big challenge. `async-oauth2-provider` implements [OAuth 2.0](https://tools.ietf.org/html/rfc6749) and can be used in [FastAPI / Starlette](https://github.com/aliev/async-oauth2-provider/tree/master/examples), aiohttp or any other asyncronous frameworks.

- [x] Can work with any databases (`MongoDB`, `PostgreSQL`, `MySQL` etc.) and ORMs ([gino](https://python-gino.org/), [sqlalchemy](https://www.sqlalchemy.org/), [databases](https://pypi.org/project/databases/)) over simple [DBBase](https://github.com/aliev/async-oauth2-provider/blob/master/src/async_oauth2_provider/db.py) interface.
- [x] This repository also contains integration examples with [FastAPI / Starlette](https://github.com/aliev/async-oauth2-provider/tree/master/examples), [aiohttp](https://github.com/aliev/async-oauth2-provider/tree/master/examples) with gino ORM.
- [x] Can be easily integrated to any asynchronous framework over simple API.

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

| Setting                               | Default value |
| ------------------------------------- | ------------- |
| OAUTH2_TOKEN_EXPIRES_IN               | 86400         |
| OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN  | 300           |
| OAUTH2_INSECURE_TRANSPORT             | False         |
