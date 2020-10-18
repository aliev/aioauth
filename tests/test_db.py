from typing import Dict

import pytest
from async_oauth2_provider.db import DBBase
from async_oauth2_provider.requests import Request
from async_oauth2_provider.types import RequestMethod


@pytest.mark.asyncio
async def test_db(storage: Dict):
    db = DBBase()
    request = Request(method=RequestMethod.POST)
    client = storage["clients"][0]
    token = storage["tokens"][0]
    authorization_code = storage["authorization_codes"][0]

    with pytest.raises(NotImplementedError):
        await db.get_token(request=request, client_id="", token="", refresh_token="")
    with pytest.raises(NotImplementedError):
        await db.get_client(request=request, client_id="", client_secret="")
    with pytest.raises(NotImplementedError):
        await db.authenticate(request=request)
    with pytest.raises(NotImplementedError):
        await db.get_authorization_code(
            request=request, client_id=client.client_id, code=""
        )
    with pytest.raises(NotImplementedError):
        await db.delete_authorization_code(
            request=request, client_id=client.client_id, code=authorization_code.code
        )
    with pytest.raises(NotImplementedError):
        await db.revoke_token(request=request, token=token)
