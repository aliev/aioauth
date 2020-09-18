## Asynchronous OAuth 2.0 framework for Python 3

`async-oauth2-provider` implements [OAuth 2.0](https://tools.ietf.org/html/rfc6749) and can be used in [FastAPI / Starlette](examples), aiohttp or any other asynchronous frameworks. It can work with any databases like `MongoDB`, `PostgreSQL`, `MySQL` and ORMs like [gino](https://python-gino.org/), [sqlalchemy](https://www.sqlalchemy.org/), [databases](https://pypi.org/project/databases/) over simple [DBBase](src/async_oauth2_provider/db.py) interface.

## Why this project exists?

There are few great OAuth frameworks for Python like [oauthlib](https://github.com/oauthlib/oauthlib) and [authlib](https://github.com/lepture/authlib), but they do not support asyncio because rewriting these libraries to asyncio is a big challenge.

[Here](examples) we implemented an integration example with FastAPI / Starlette. If you want to add more examples, please welcome to [contribution](CONTRIBUTING.rst)!

## Supported RFCs

- [x] [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [ ] [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [ ] [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)
- [ ] [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)

```
python -m pip install async-oauth2-provider
```

## Settings and defaults

| Setting                               | Default value | Description                                                                                                         |
| ------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------- |
| OAUTH2_TOKEN_EXPIRES_IN               | 86400         | Access token lifetime. Default value in seconds.                                                                    |
| OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN  | 300           | Authorization code lifetime. Default value in seconds.                                                              |
| OAUTH2_INSECURE_TRANSPORT             | False         | Allow connections over SSL only. When this option is disabled server will raise "HTTP method is not allowed" error. |
