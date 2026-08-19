import pytest

from aioauth.errors import InvalidGrantError
from tests.formal_bridge.rfc6749 import (
    AUTH_CODE_TRACE_PATTERN,
    exchange_authorization_code,
    replay_authorization_code_traces,
)
from tests.formal_bridge.itf import load_states


@pytest.mark.asyncio
async def test_authorization_code_bridge_accepts_matching_redirect_uri():
    response = await exchange_authorization_code(
        code_redirect_uri="https://client.example/callback-a",
        token_redirect_uri="https://client.example/callback-a",
    )

    assert response.access_token
    assert response.refresh_token


@pytest.mark.asyncio
async def test_authorization_code_bridge_rejects_registered_but_mismatched_redirect_uri():
    with pytest.raises(InvalidGrantError):
        await exchange_authorization_code(
            code_redirect_uri="https://client.example/callback-a",
            token_redirect_uri="https://client.example/callback-b",
        )


@pytest.mark.asyncio
async def test_authorization_code_bridge_replays_generated_quint_traces():
    if not load_states(AUTH_CODE_TRACE_PATTERN):
        pytest.skip("generate Quint traces with formal/README.md commands")

    checked = await replay_authorization_code_traces()

    assert checked
