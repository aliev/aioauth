import pytest

from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import Request
from aioauth.storage import BaseStorage


@pytest.mark.asyncio
async def test_storage_class(storage):
    db = BaseStorage()
    request = Request(method="POST")
    client: Client = storage["clients"][0]
    token: Token = storage["tokens"][0]
    authorization_code: AuthorizationCode = storage["authorization_codes"][0]

    with pytest.raises(NotImplementedError):
        await db.create_token(
            request=request,
            client_id=client.client_id,
            scope="",
            access_token=token.access_token,
            refresh_token=token.refresh_token,
        )

    with pytest.raises(NotImplementedError):
        await db.create_authorization_code(
            client_id=client.client_id,
            code="123",
            code_challenge=None,
            code_challenge_method=None,
            nonce="nonce",
            redirect_uri="",
            request=request,
            response_type="",
            scope="",
        )

    with pytest.raises(NotImplementedError):
        await db.get_token(
            request=request,
            client_id=client.client_id,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
        )
    with pytest.raises(NotImplementedError):
        await db.get_client(
            request=request,
            client_id=client.client_id,
            client_secret=client.client_secret,
        )
    with pytest.raises(NotImplementedError):
        await db.authenticate(request=request)
    with pytest.raises(NotImplementedError):
        await db.get_authorization_code(
            request=request, client_id=client.client_id, code=authorization_code.code
        )
    with pytest.raises(NotImplementedError):
        await db.delete_authorization_code(
            request=request, client_id=client.client_id, code=authorization_code.code
        )
    with pytest.raises(NotImplementedError):
        await db.revoke_token(request=request, refresh_token=token.refresh_token)

    with pytest.raises(NotImplementedError):
        await db.get_id_token(
            request=request,
            client_id=client.client_id,
            scope="",
            response_type="token",
            redirect_uri="",
            nonce="",
        )
