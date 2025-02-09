import pytest

from aioauth.errors import InvalidGrantError
from aioauth.grant_type import RefreshTokenGrantType
from aioauth.requests import Post, Request
from aioauth.utils import encode_auth_headers


@pytest.mark.asyncio
async def test_refresh_token_grant_type(context):
    client = context.clients[0]
    client_id = client.client_id
    client_secret = client.client_secret
    token = context.initial_tokens[0]
    refresh_token = token.refresh_token
    access_token = token.access_token
    request_url = "https://localhost"
    db = context.storage

    post = Post(
        grant_type="refresh_token",
        refresh_token=refresh_token,
        scope=client.scope,
    )

    request = Request(
        url=request_url,
        post=post,
        method="POST",
        headers=encode_auth_headers(client_id, client_secret),
    )

    grant_type = RefreshTokenGrantType(
        db, client_id=client_id, client_secret=client_secret
    )

    client = await grant_type.validate_request(request)

    assert client.client_id == client_id
    assert client.client_secret == client_secret

    token_response = await grant_type.create_token_response(request, client)

    # Check that previous token was revoken
    token_in_db = await db.get_token(
        request=request,
        client_id=client_id,
        access_token=access_token,
        refresh_token=refresh_token,
    )
    assert token_in_db.revoked
    assert token_response.scope == client.scope

    with pytest.raises(InvalidGrantError):
        token_response = await grant_type.create_token_response(request, client)
