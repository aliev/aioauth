import time
from typing import Dict

import pytest

from aioauth.config import Settings
from aioauth.errors import InvalidGrantError
from aioauth.grant_type import RefreshTokenGrantType
from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import Post, Request
from aioauth.server import AuthorizationServer
from aioauth.utils import encode_auth_headers

from tests.classes import BasicServerConfig, Storage


@pytest.fixture
def storage(defaults: BasicServerConfig, settings: Settings) -> Dict:
    client = Client(
        client_id=defaults.client_id,
        client_secret=defaults.client_secret,
        grant_types=[
            "authorization_code",
            "password",
            "client_credentials",
            "refresh_token",
        ],
        redirect_uris=[defaults.redirect_uri],
        response_types=["code", "token"],
        scope="read write foo",
    )

    authorization_code = AuthorizationCode(
        code=defaults.code,
        client_id=defaults.client_id,
        response_type="code",
        auth_time=int(time.time()),
        redirect_uri=defaults.redirect_uri,
        scope="read write",
        code_challenge_method="plain",
        expires_in=settings.AUTHORIZATION_CODE_EXPIRES_IN,
    )

    token = Token(
        client_id=defaults.client_id,
        expires_in=settings.TOKEN_EXPIRES_IN,
        refresh_token_expires_in=settings.REFRESH_TOKEN_EXPIRES_IN,
        access_token=defaults.access_token,
        refresh_token=defaults.refresh_token,
        issued_at=int(time.time()),
        scope="read write",
    )

    return {
        "tokens": [token],
        "authorization_codes": [authorization_code],
        "clients": [client],
    }


@pytest.mark.asyncio
async def test_refresh_token_grant_type(
    server: AuthorizationServer, defaults: BasicServerConfig, db: Storage
):
    client_id = defaults.client_id
    client_secret = defaults.client_secret
    request_url = "https://localhost"

    post = Post(
        grant_type="refresh_token",
        refresh_token=defaults.refresh_token,
        scope=defaults.scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )

    grant_type = RefreshTokenGrantType[Request, Storage](
        db, client_id=defaults.client_id, client_secret=defaults.client_secret
    )

    client = await grant_type.validate_request(request)

    assert client.client_id == client_id
    assert client.client_secret == client_secret

    token_response = await grant_type.create_token_response(request, client)

    # Check that previous token was revoken
    token_in_db = await db.get_token(
        request=request,
        client_id=client_id,
        access_token=defaults.access_token,
        refresh_token=defaults.refresh_token,
    )
    assert token_in_db.revoked  # type: ignore
    assert token_response.scope == defaults.scope

    with pytest.raises(InvalidGrantError):
        token_response = await grant_type.create_token_response(request, client)
