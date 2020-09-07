## Asynchronous OAuth2 Provider library

This package implements [OAuth 2.0 specification](https://tools.ietf.org/html/rfc6749).

Why this project exists

Installation

```
python -m pip install async-oauth2-provider
```

Supported or planned features

- [x] [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [ ] [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [ ] [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)
- [ ] [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)

Library settings

OAUTH2_TOKEN_EXPIRES_IN
OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN
OAUTH2_INSECURE_TRANSPORT

You have to inherit from DBBase class

```python
class PostgreSQL(DBBase):
    async def create_token(self, request: Request, client: Client) -> Token:
        token = super().create_token(self, request, client)
        return token

    async def create_authorization_code(self, request: Request, client: Client) -> AuthorizationCode:
        authorization_code = create_authorization_code(self, request, client)
        return authorization_code

    async def get_client(self, request: Request, client_id: str, client_secret: Optional[str] = None) -> Optional[Client]:
        client_record = ...
        client = Client.from_orm(client_record)
        return client

    async def get_user(self, request: Request) -> bool:
        return True

    async def get_authorization_code(self, request: Request, client: Client) -> Optional[AuthorizationCode]:
        authorization_code_record = ...
        authorization_code = AuthorizationCode.from_orm(authorization_code_record)
        return authorization_code

    async def delete_authorization_code(self, request: Request, authorization_code: AuthorizationCode):
        ...

    async def get_refresh_token(self, request: Request, client: Client) -> Optional[Token]:
        token_record = ...
        token = Token.from_orm(token_record)
        return token

    async def revoke_token(self, request: Request, token: Token):
        token_record = ...
```

Creating the base endpoint instance

```python
db = PostgreSQL()
oauth2_endpoint = OAuth2Endpoint(db)
```

Registering endpoints

```python
# Registering Token response type
endpoint.register(EndpointType.RESPONSE_TYPE, ResponseType.TYPE_TOKEN, ResponseTypeToken)

# Registering Authorization Code grant type
endpoint.register(EndpointType.GRANT_TYPE, GrantType.TYPE_AUTHORIZATION_CODE, AuthorizationCodeGrantType)
```


Similar projects

[https://github.com/oauthlib/oauthlib](https://github.com/oauthlib/oauthlib)

[https://github.com/lepture/authlib](https://github.com/lepture/authlib)
