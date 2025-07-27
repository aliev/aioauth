"""
Different OAuth 2.0 grant types with OpenID Connect extensions.

```python
from aioauth.oidc.core import grant_type
```
"""

from typing import TYPE_CHECKING

from ...grant_type import (
    AuthorizationCodeGrantType as OAuth2AuthorizationCodeGrantType,
)
from ...models import Client
from ...oidc.core.responses import TokenResponse
from ...requests import Request
from ...utils import generate_token


class AuthorizationCodeGrantType(OAuth2AuthorizationCodeGrantType):
    """
    The Authorization Code grant type is used by confidential and public
    clients to exchange an authorization code for an access token. After
    the user returns to the client via the redirect URL, the application
    will get the authorization code from the URL and use it to request
    an access token.
    It is recommended that all clients use [RFC 7636](https://tools.ietf.org/html/rfc7636).
    Proof Key for Code Exchange extension with this flow as well to
    provide better security.

    Note:
        Note that `aioauth` implements RFC 7636 out-of-the-box.
        See [RFC 6749 section 1.3.1](https://tools.ietf.org/html/rfc6749#section-1.3.1).
    """

    async def create_token_response(
        self, request: Request, client: Client
    ) -> TokenResponse:
        """
        Creates token response to reply to client.

        Extends the OAuth2 authorization_code grant type such that an id_token
        is always included with the access_token.

        See: [https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
        """
        if self.scope is None:
            raise RuntimeError("validate_request() must be called first")

        token = await self.storage.create_token(
            request=request,
            client_id=client.client_id,
            scope=self.scope,
            access_token=generate_token(42),
            refresh_token=generate_token(48),
        )

        if TYPE_CHECKING:
            # validate_request will have already ensured the request includes a code.
            assert request.post.code is not None

        authorization_code = await self.storage.get_authorization_code(
            request=request,
            client_id=client.client_id,
            code=request.post.code,
        )

        if TYPE_CHECKING:
            # validate_request will have already ensured the code was valid.
            assert authorization_code is not None

        id_token = await self.storage.get_id_token(
            client_id=client.client_id,
            nonce=authorization_code.nonce,
            redirect_uri=request.query.redirect_uri,
            request=request,
            response_type="code",
            scope=self.scope,
        )

        await self.storage.delete_authorization_code(
            request=request,
            client_id=client.client_id,
            code=request.post.code,
        )

        return TokenResponse(
            access_token=token.access_token,
            expires_in=token.expires_in,
            id_token=id_token,
            refresh_token=token.refresh_token,
            refresh_token_expires_in=token.refresh_token_expires_in,
            scope=token.scope,
            token_type=token.token_type,
        )
