import pytest

from aioauth.models import AuthorizationCode, Client, Token
from aioauth.requests import Request
from aioauth.storage import BaseStorage

from tests import factories


@pytest.mark.asyncio
async def test_storage_class() -> None:
    db = BaseStorage()
    request = Request(method="POST")
    client: Client = factories.client_factory()
    token: Token = factories.token_factory()
    authorization_code: AuthorizationCode = factories.authorization_code_factory()

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
            request=request,
            client_id=client.client_id,
            scope="",
            response_type="token",
            redirect_uri="",
            code_challenge_method=None,
            code_challenge=None,
            code="123",
        )

    with pytest.raises(NotImplementedError):
        await db.get_token(
            request=request,
            client_id=client.client_id,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            token_type="refresh_token",
        )
    with pytest.raises(NotImplementedError):
        await db.get_client(
            request=request,
            client_id=client.client_id,
            client_secret=client.client_secret,
        )
    with pytest.raises(NotImplementedError):
        await db.get_user(request=request)
    with pytest.raises(NotImplementedError):
        await db.get_authorization_code(
            request=request, client_id=client.client_id, code=authorization_code.code
        )
    with pytest.raises(NotImplementedError):
        await db.delete_authorization_code(
            request=request, client_id=client.client_id, code=authorization_code.code
        )
    with pytest.raises(NotImplementedError):
        await db.revoke_token(
            request=request,
            client_id=client.client_id,
            refresh_token=token.refresh_token,
            token_type=None,
            access_token=None,
        )

    with pytest.raises(NotImplementedError):
        await db.get_id_token(
            request=request,
            client_id=client.client_id,
            scope="",
            response_type="token",
            redirect_uri="",
            nonce="",
        )
