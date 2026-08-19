import asyncio
import subprocess
import time
from pathlib import Path
from typing import Optional, Literal, Dict

from aioauth.errors import OAuth2Error
from aioauth.grant_type import AuthorizationCodeGrantType, RefreshTokenGrantType
from aioauth.models import AuthorizationCode
from aioauth.requests import Post, Request
from aioauth.utils import create_s256_code_challenge, generate_token
from tests import factories
from tests.formal_bridge.itf import ItfState, action_states, tag


FORMAL_ROOT = Path("formal/rfc6749")
TRACE_ROOT = FORMAL_ROOT / "traces"
AUTH_CODE_TRACE_PATTERN = str(TRACE_ROOT / "auth-code*.itf.json")
REFRESH_TOKEN_TRACE_PATTERN = str(TRACE_ROOT / "refresh-token*.itf.json")

REDIRECT_URIS = {
    "UriA": "https://client.example/callback-a",
    "UriB": "https://client.example/callback-b",
}

SCOPE_REQUESTS = {
    "Omitted": "",
    "SameScope": "read write",
    "SubsetScope": "read",
    "ExtraScope": "admin",
}

PKCE_METHODS: Dict[str, Optional[Literal["plain", "S256"]]] = {
    "NoPkce": None,
    "Plain": "plain",
    "S256": "S256",
}


def run_quint_generate_traces(n_traces: int = 100) -> None:
    TRACE_ROOT.mkdir(parents=True, exist_ok=True)
    commands = [
        [
            "quint",
            "run",
            str(FORMAL_ROOT / "authorization_code_pkce.qnt"),
            "--mbt",
            f"--n-traces={n_traces}",
            f"--out-itf={TRACE_ROOT / 'auth-code.itf.json'}",
            "--invariant=authorizationCodeSafety",
        ],
        [
            "quint",
            "run",
            str(FORMAL_ROOT / "refresh_token_rotation.qnt"),
            "--mbt",
            f"--n-traces={n_traces}",
            f"--out-itf={TRACE_ROOT / 'refresh-token.itf.json'}",
            "--invariant=refreshTokenSafety",
        ],
    ]
    for command in commands:
        subprocess.run(command, check=True)


def run_quint_verify() -> None:
    commands = [
        [
            "quint",
            "verify",
            str(FORMAL_ROOT / "authorization_code_pkce.qnt"),
            "--invariant=authorizationCodeSafety",
        ],
        [
            "quint",
            "verify",
            str(FORMAL_ROOT / "refresh_token_rotation.qnt"),
            "--invariant=refreshTokenSafety",
        ],
    ]
    for command in commands:
        subprocess.run(command, check=True)


async def exchange_authorization_code(
    *,
    code_redirect_uri: str,
    token_redirect_uri: str,
    code_challenge_method: Optional[Literal["plain", "S256"]] = None,
    code_verifier: Optional[str] = None,
    expired: bool = False,
    client_matches: bool = True,
    code_present: bool = True,
    grant_allowed: bool = True,
    scope_allowed: bool = True,
):
    client = factories.client_factory(
        client_secret="",
        redirect_uris=[
            REDIRECT_URIS["UriA"],
            REDIRECT_URIS["UriB"],
        ],
        grant_types=(["authorization_code"] if grant_allowed else ["refresh_token"]),
        scope="scope",
    )
    code = generate_token(42)
    verifier = "verifier"
    code_challenge = None
    if code_challenge_method == "plain":
        code_challenge = verifier
    elif code_challenge_method == "S256":
        code_challenge = create_s256_code_challenge(verifier)

    authorization_code = AuthorizationCode(
        auth_time=0 if expired else factories.auth_time_factory(),
        client_id=client.client_id,
        code=code,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_in=1 if expired else 300,
        redirect_uri=code_redirect_uri,
        response_type="code",
        scope=client.scope,
    )
    if expired:
        authorization_code.auth_time = int(time.time()) - 3600

    initial_authorization_codes = [authorization_code]
    if not code_present:
        missing_code = AuthorizationCode(
            auth_time=authorization_code.auth_time,
            client_id=client.client_id,
            code=f"other-{code}",
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_in=authorization_code.expires_in,
            redirect_uri=code_redirect_uri,
            response_type="code",
            scope=client.scope,
        )
        initial_authorization_codes = [missing_code]

    context = factories.context_factory(
        clients=[client],
        initial_authorization_codes=initial_authorization_codes,
        initial_tokens=[],
    )
    client_id = client.client_id if client_matches else "unknown-client"
    request = Request(
        url="https://localhost",
        method="POST",
        post=Post(
            client_id=client_id,
            code=code if code_present else None,
            code_verifier=code_verifier,
            grant_type="authorization_code",
            redirect_uri=token_redirect_uri,
            scope=client.scope if scope_allowed else "scope extra",
        ),
    )
    grant_type = AuthorizationCodeGrantType(
        context.storage,
        client_id=client_id,
        client_secret="",
    )

    validated_client = await grant_type.validate_request(request)
    return await grant_type.create_token_response(request, validated_client)


async def exchange_refresh_token(
    *,
    old_scope: str = "read write",
    requested_scope: str = "",
    grant_allowed: bool = True,
    token_exists: bool = True,
    old_token_revoked: bool = False,
    old_token_expired: bool = False,
    client_matches: bool = True,
    refresh_token_present: bool = True,
):
    client = factories.client_factory(
        grant_types=(["refresh_token"] if grant_allowed else ["authorization_code"]),
        scope="read write admin",
    )
    token = factories.token_factory(
        client_id=client.client_id,
        scope=old_scope,
    )
    token.revoked = old_token_revoked
    if old_token_expired:
        token.issued_at = int(time.time()) - token.refresh_token_expires_in - 1

    initial_tokens = [token]
    if not token_exists:
        initial_tokens = [
            factories.token_factory(
                client_id=client.client_id,
                refresh_token=f"other-{token.refresh_token}",
                scope=old_scope,
            )
        ]

    context = factories.context_factory(
        clients=[client],
        initial_tokens=initial_tokens,
        initial_authorization_codes=[],
    )
    client_id = client.client_id if client_matches else "unknown-client"
    request = Request(
        url="https://localhost",
        method="POST",
        post=Post(
            client_id=client_id,
            grant_type="refresh_token",
            refresh_token=token.refresh_token if refresh_token_present else None,
            scope=requested_scope,
        ),
    )
    grant_type = RefreshTokenGrantType(
        context.storage,
        client_id=client_id,
        client_secret=client.client_secret,
    )

    client = await grant_type.validate_request(request)
    response = await grant_type.create_token_response(request, client)
    old_token = await context.storage.get_token(
        request=request,
        client_id=client.client_id,
        refresh_token=token.refresh_token,
        token_type="refresh_token",
    )
    return response, old_token


def authorization_code_exchange_from_state(state: ItfState):
    code_issued = state["codeIssued"]
    pkce_mode = tag(state["codePkceMode"])
    code_challenge_method = PKCE_METHODS[pkce_mode]
    verifier_matches = state["tokenVerifierMatches"]
    verifier_present = state["tokenVerifierPresent"]
    code_verifier = "verifier" if verifier_present else None
    if pkce_mode != "NoPkce" and not verifier_matches:
        code_verifier = "wrong-verifier" if verifier_present else None

    return exchange_authorization_code(
        code_redirect_uri=REDIRECT_URIS[tag(state["codeRedirectUri"])],
        token_redirect_uri=REDIRECT_URIS[tag(state["tokenRedirectUri"])],
        code_challenge_method=code_challenge_method,
        code_verifier=code_verifier,
        expired=state["codeExpired"],
        client_matches=state["tokenClientMatches"],
        code_present=code_issued and state["tokenCodePresent"],
        grant_allowed=state["tokenGrantAllowed"],
        scope_allowed=state["tokenScopeAllowed"],
    )


def refresh_token_exchange_from_state(state: ItfState):
    scope_request = tag(state["scopeRequest"])
    return exchange_refresh_token(
        requested_scope=SCOPE_REQUESTS[scope_request],
        grant_allowed=state["grantAllowed"],
        token_exists=state["oldTokenExists"],
        old_token_revoked=state["oldTokenRevokedBefore"],
        old_token_expired=state["oldTokenExpired"],
        client_matches=state["clientMatches"],
        refresh_token_present=state["refreshTokenPresent"],
    )


async def replay_authorization_code_traces(
    pattern: str = AUTH_CODE_TRACE_PATTERN,
) -> int:
    checked = 0
    for state in action_states(pattern, "exchangeAuthorizationCode"):
        checked += 1
        exchange = authorization_code_exchange_from_state(state)
        if state["tokenIssued"]:
            response = await exchange
            assert response.access_token
            assert response.refresh_token
        else:
            try:
                await exchange
            except OAuth2Error:
                pass
            else:
                raise AssertionError(
                    f"{state.trace_path}:{state.index} accepted invalid request"
                )
    return checked


async def replay_refresh_token_traces(
    pattern: str = REFRESH_TOKEN_TRACE_PATTERN,
) -> int:
    checked = 0
    for state in action_states(pattern, "exchangeRefreshToken"):
        checked += 1
        exchange = refresh_token_exchange_from_state(state)
        if state["tokenIssued"]:
            response, old_token = await exchange
            new_scope = tag(state["newScope"])
            if new_scope == "OldScope":
                assert response.scope == "read write"
            elif new_scope == "RequestedSubset":
                assert response.scope == "read"
            else:
                raise AssertionError(
                    f"{state.trace_path}:{state.index} unexpected newScope {new_scope}"
                )
            assert old_token.revoked
        else:
            try:
                await exchange
            except OAuth2Error:
                pass
            else:
                raise AssertionError(
                    f"{state.trace_path}:{state.index} accepted invalid request"
                )
    return checked


async def replay_all_traces() -> int:
    auth_count, refresh_count = await asyncio.gather(
        replay_authorization_code_traces(),
        replay_refresh_token_traces(),
    )
    return auth_count + refresh_count
