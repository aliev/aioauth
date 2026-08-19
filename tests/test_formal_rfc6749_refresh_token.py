import pytest

from aioauth.errors import InvalidGrantError, InvalidScopeError
from aioauth.grant_type import RefreshTokenGrantType
from aioauth.requests import Post, Request
from tests import factories
from tests.formal_bridge.itf import load_states
from tests.formal_bridge.rfc6749 import (
    REFRESH_TOKEN_TRACE_PATTERN,
    exchange_refresh_token,
    replay_refresh_token_traces,
)


@pytest.mark.asyncio
async def test_refresh_token_bridge_preserves_scope_when_omitted():
    response, old_token = await exchange_refresh_token(
        old_scope="read write",
        requested_scope="",
    )

    assert response.scope == "read write"
    assert old_token.revoked


@pytest.mark.asyncio
async def test_refresh_token_bridge_allows_scope_subset():
    response, old_token = await exchange_refresh_token(
        old_scope="read write",
        requested_scope="read",
    )

    assert response.scope == "read"
    assert old_token.revoked


@pytest.mark.asyncio
async def test_refresh_token_bridge_rejects_scope_not_originally_granted():
    with pytest.raises(InvalidScopeError):
        await exchange_refresh_token(
            old_scope="read",
            requested_scope="write",
        )


@pytest.mark.asyncio
async def test_refresh_token_bridge_invalid_scope_does_not_revoke_old_token():
    client = factories.client_factory(
        grant_types=["refresh_token"],
        scope="read write",
    )
    token = factories.token_factory(
        client_id=client.client_id,
        scope="read",
    )
    context = factories.context_factory(
        clients=[client],
        initial_tokens=[token],
        initial_authorization_codes=[],
    )
    request = Request(
        url="https://localhost",
        method="POST",
        post=Post(
            client_id=client.client_id,
            grant_type="refresh_token",
            refresh_token=token.refresh_token,
            scope="write",
        ),
    )
    grant_type = RefreshTokenGrantType(
        context.storage,
        client_id=client.client_id,
        client_secret=client.client_secret,
    )

    validated_client = await grant_type.validate_request(request)
    with pytest.raises(InvalidScopeError):
        await grant_type.create_token_response(request, validated_client)

    old_token = await context.storage.get_token(
        request=request,
        client_id=client.client_id,
        refresh_token=token.refresh_token,
        token_type="refresh_token",
    )
    assert not old_token.revoked


@pytest.mark.asyncio
async def test_refresh_token_bridge_rejects_reuse_after_rotation():
    client = factories.client_factory(scope="read write")
    token = factories.token_factory(
        client_id=client.client_id,
        scope="read",
    )
    context = factories.context_factory(
        clients=[client],
        initial_tokens=[token],
        initial_authorization_codes=[],
    )
    request = Request(
        url="https://localhost",
        method="POST",
        post=Post(
            client_id=client.client_id,
            grant_type="refresh_token",
            refresh_token=token.refresh_token,
            scope="read",
        ),
    )
    grant_type = RefreshTokenGrantType(
        context.storage,
        client_id=client.client_id,
        client_secret=client.client_secret,
    )

    client = await grant_type.validate_request(request)
    await grant_type.create_token_response(request, client)

    with pytest.raises(InvalidGrantError):
        await grant_type.create_token_response(request, client)


@pytest.mark.asyncio
async def test_refresh_token_bridge_replays_generated_quint_traces():
    if not load_states(REFRESH_TOKEN_TRACE_PATTERN):
        pytest.skip("generate Quint refresh-token traces with formal/README.md")

    checked = await replay_refresh_token_traces()

    assert checked
