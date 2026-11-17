import asyncio
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AuthorizationParams, TokenError
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from redis.asyncio.lock import Lock
from redis.exceptions import LockNotOwnedError
from starlette.requests import Request

from lightdash_mcp.auth import provider as provider_module
from lightdash_mcp.auth import store as store_module
from lightdash_mcp.auth.provider import (
    CLIENT_TTL,
    GRANT_LIFETIME,
    REFRESH_TTL,
    TRANSACTION_TTL,
    Access,
    Grant,
    LightdashOAuthProvider,
    Refresh,
    RefreshFailed,
    Rotated,
    SignInRequired,
    Transaction,
    _consent_cookie,
)
from lightdash_mcp.auth.store import Store, digest
from lightdash_mcp.tools.common import BUSY, RECONNECT, UNREACHABLE, lightdash

from .conftest import (
    LIGHTDASH,
    REDIRECT,
    REFRESHED,
    REVOKE_URL,
    TOKEN_URL,
    add_code,
    token_response,
)

CLIENT = OAuthClientInformationFull(client_id="client", redirect_uris=[REDIRECT])
CLIENT_FIELDS = {"client_id": "client"}
ORG_URL = f"{LIGHTDASH}/api/v1/org"
USER_URL = f"{LIGHTDASH}/api/v1/user"

# How long the Lightdash access token of a new grant lasts: fresh, or about to be refreshed.
FRESH = 3600
EXPIRING = 10
REFRESH_EXPIRY = 600


async def add_grant(
    provider: LightdashOAuthProvider,
    expires_in: float,
    grant_id: str = "grant",
    subject: str = "user",
) -> str:
    """A grant with an access token and a refresh token, both named after it. Returns the access
    token."""
    access = f"our-access-{grant_id}"
    refresh = f"our-refresh-{grant_id}"
    grant = Grant(
        client_id="client",
        subject=subject,
        access_token=f"ld-access-{grant_id}",
        refresh_token=f"ld-refresh-{grant_id}",
        expires_at=time.time() + expires_in,
        access_digest=digest(access),
        refresh_digest=digest(refresh),
    )
    common = {
        "client_id": "client",
        "scopes": [],
        "subject": subject,
        "grant_id": grant_id,
    }
    refresh_expires_at = int(time.time()) + REFRESH_EXPIRY

    await provider.store.put("grant", grant_id, grant)
    await provider.store.put("access", digest(access), Access(token=access, **common))
    await provider.store.put(
        "refresh",
        digest(refresh),
        Refresh(token=refresh, expires_at=refresh_expires_at, **common),
    )

    return access


async def grant_of(provider: LightdashOAuthProvider, grant_id: str = "grant") -> Grant | None:
    return await provider.store.get("grant", grant_id, Grant)


async def refresh_of(provider: LightdashOAuthProvider, grant_id: str = "grant") -> Refresh:
    return await provider.load_refresh_token(CLIENT, f"our-refresh-{grant_id}")


async def is_grant_locked(provider: LightdashOAuthProvider) -> bool:
    lock = provider.store.lock("grant", "grant")

    return await lock.locked()


async def revoke_access(provider: LightdashOAuthProvider, access_token: str) -> None:
    access = await provider.load_access_token(access_token)

    await provider.revoke_token(access)


@asynccontextmanager
async def signed_in(provider: LightdashOAuthProvider, access_token: str):
    """Run the block as the user of `access_token`, as the SDK's bearer middleware does."""
    access = await provider.load_access_token(access_token)
    context = auth_context_var.set(AuthenticatedUser(access))

    try:
        yield
    finally:
        auth_context_var.reset(context)


def audit_events(caplog: pytest.LogCaptureFixture) -> list[str]:
    records = [record for record in caplog.records if record.name == "lightdash_mcp.audit"]

    return [json.loads(record.getMessage())["event"] for record in records]


async def get_org(provider: LightdashOAuthProvider) -> Any:
    """A tool's call to Lightdash, as the signed-in user."""
    async with lightdash(provider) as lightdash_client:
        return await lightdash_client.get("/api/v1/org")


async def enter_lightdash(provider: LightdashOAuthProvider) -> None:
    """What every tool does before it calls Lightdash: get the signed-in user's token."""
    async with lightdash(provider):
        pass


def approved_transaction(state: str | None) -> Transaction:
    params = AuthorizationParams(
        state=state,
        scopes=[],
        code_challenge="x" * 43,
        redirect_uri=REDIRECT,
        redirect_uri_provided_explicitly=True,
    )

    return Transaction(
        client_id="client",
        params=params,
        verifier="verifier",
        csrf="csrf",
        approved=True,
    )


def callback_request(transaction_id: str) -> Request:
    cookie = f"{_consent_cookie(transaction_id)}=csrf"
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/oauth/lightdash/callback",
        "query_string": f"state={transaction_id}&code=lightdash-code".encode(),
        "headers": [(b"cookie", cookie.encode())],
    }

    return Request(scope)


def consent_request(query: bytes) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/oauth/consent",
        "query_string": query,
        "headers": [],
    }

    return Request(scope)


async def test_stored_values_are_encrypted(provider):
    await add_grant(provider, FRESH)

    raw = await provider.store._redis.get("lightdash-mcp:grant:grant")

    assert b"ld-refresh" not in raw


async def test_values_from_another_key_count_as_missing(provider):
    access = await add_grant(provider, FRESH)
    other_key = Fernet.generate_key().decode()
    other = Store(provider.store._redis, other_key)

    read = await other.get("access", digest(access), Access)
    popped = await other.pop("grant", "grant", Grant)

    assert read is None
    assert popped is None


async def test_fresh_token_is_used_as_is(provider):
    await add_grant(provider, FRESH)

    token = await provider.lightdash_token("grant")

    assert token == "ld-access-grant"


@respx.mock
async def test_concurrent_requests_refresh_once(provider):
    await add_grant(provider, EXPIRING)
    route = respx.post(TOKEN_URL).mock(return_value=token_response())
    requests = [provider.lightdash_token("grant") for _ in range(5)]

    tokens = await asyncio.gather(*requests)

    sent = route.calls[0].request.content
    grant = await grant_of(provider)
    assert tokens == ["ld-access-2"] * 5
    assert route.call_count == 1
    assert b"refresh_token=ld-refresh-grant" in sent
    assert grant.refresh_token == "ld-refresh-2"


@respx.mock
async def test_refused_refresh_ends_the_sign_in(provider):
    access = await add_grant(provider, EXPIRING)
    refused = httpx.Response(401, json={"error": "invalid_grant"})
    respx.post(TOKEN_URL).mock(return_value=refused)

    with pytest.raises(SignInRequired):
        await provider.lightdash_token("grant")

    grant = await grant_of(provider)
    loaded = await provider.load_access_token(access)
    assert grant is None
    assert loaded is None


async def test_access_token_is_tied_to_its_grant(provider):
    access = await add_grant(provider, FRESH)

    loaded = await provider.load_access_token(access)

    assert loaded.subject == "user"

    await provider.end_grant("grant", "test")

    ended = await provider.load_access_token(access)
    assert ended is None


@respx.mock
async def test_revoke_ends_the_grant_upstream_too(provider, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    access = await add_grant(provider, FRESH)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

    await revoke_access(provider, access)

    loaded = await provider.load_access_token(access)
    body = revoke.calls[0].request.content.decode()
    sent = dict(httpx.QueryParams(body))
    assert loaded is None
    # Lightdash's client credentials, as RFC 7009 asks of a confidential client.
    assert sent == {
        "token": "ld-refresh-grant",
        "token_type_hint": "refresh_token",
        "client_id": "id",
        "client_secret": "secret",
    }
    assert "lightdash_revoke_failed" not in caplog.text


async def test_a_second_revocation_of_an_ended_grant_logs_nothing(provider, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    access = await add_grant(provider, FRESH)
    token = await provider.load_access_token(access)
    await provider.end_grant("grant", "test")

    await provider.revoke_token(token)

    events = audit_events(caplog)
    assert events == ["grant_ended"]


@respx.mock
async def test_a_revocation_that_outlasts_its_lock_still_finishes(provider, caplog, monkeypatch):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    access = await add_grant(provider, FRESH)
    token = await provider.load_access_token(access)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

    async def release_an_expired_lock(self):
        raise LockNotOwnedError("Cannot release a lock that's no longer owned")

    monkeypatch.setattr(Lock, "release", release_an_expired_lock)

    await provider.revoke_token(token)

    events = audit_events(caplog)
    loaded = await provider.load_access_token(access)
    assert events == ["token_revoked", "grant_ended"]
    assert loaded is None
    assert revoke.called


@respx.mock
async def test_refused_upstream_revocation_is_logged(provider, caplog):
    access = await add_grant(provider, FRESH)
    refused = httpx.Response(401, json={"error": "invalid_client"})
    respx.post(REVOKE_URL).mock(return_value=refused)

    await revoke_access(provider, access)

    loaded = await provider.load_access_token(access)
    assert loaded is None
    assert '"event": "lightdash_revoke_failed"' in caplog.text
    assert '"failure": 401' in caplog.text


@respx.mock
async def test_tools_map_lightdash_errors(provider):
    access = await add_grant(provider, FRESH)
    denied = {"status": "error", "error": {"message": "Not allowed"}}
    forbidden = httpx.Response(403, json=denied)
    refused = httpx.Response(401, json={"error": {"message": "No"}})

    async with signed_in(provider, access):
        respx.get(ORG_URL).mock(return_value=forbidden)

        with pytest.raises(ToolError, match="Permission denied.*Not allowed"):
            await get_org(provider)

        # Still refused with a refreshed token: Lightdash renewed the sign-in, so the 401 is about
        # something else, such as an Enterprise-only route or a proxy. The sign-in stays.
        respx.post(TOKEN_URL).mock(return_value=REFRESHED)
        respx.get(ORG_URL).mock(return_value=refused)

        with pytest.raises(ToolError, match=r"Lightdash refused this request \(401\): No"):
            await get_org(provider)

        loaded = await provider.load_access_token(access)
        grant = await grant_of(provider)
        assert loaded
        assert grant.access_token == "ld-access-2"


@respx.mock
async def test_refresh_errors_read_the_same_before_and_during_a_call(provider):
    access = await add_grant(provider, FRESH)
    try_again = "Lightdash error 503 while refreshing your sign-in. Try again"

    async with signed_in(provider, access):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(503))
        respx.get(ORG_URL).mock(return_value=httpx.Response(401))

        with pytest.raises(ToolError, match=try_again):
            await get_org(provider)

        grant = await grant_of(provider)
        expired = grant.model_copy(update={"expires_at": 0})
        await provider.store.put("grant", "grant", expired)

        with pytest.raises(ToolError, match=try_again):
            await enter_lightdash(provider)

        loaded = await provider.load_access_token(access)
        assert loaded


async def refresh_answering(provider: LightdashOAuthProvider, answer: httpx.Response) -> None:
    """A tool's refresh that gets `answer` from Lightdash, which must ask to try again."""
    respx.post(TOKEN_URL).mock(return_value=answer)

    with pytest.raises(ToolError, match="no token. Try again in a moment"):
        await enter_lightdash(provider)


@respx.mock
async def test_malformed_refresh_answer_is_a_retryable_tool_error(provider):
    access = await add_grant(provider, EXPIRING)
    answers = [
        httpx.Response(200, json={"access_token": "only"}),
        httpx.Response(200, text="<html>"),
        httpx.Response(200, json=[1]),
    ]

    async with signed_in(provider, access):
        for answer in answers:
            await refresh_answering(provider, answer)

        grant = await grant_of(provider)
        assert grant.refresh_token == "ld-refresh-grant"


async def test_a_lock_finds_its_own_token_after_a_lost_answer(provider, monkeypatch):
    monkeypatch.setattr(store_module, "LOCK_WAIT", 0.1)
    lock = provider.store.lock("grant", "grant")
    another_lock = provider.store.lock("grant", "grant")
    # As a SET NX that Redis applied, but whose answer was lost, leaves it for the retry.
    await lock.redis.set(lock.name, b"mine", px=60_000)

    acquired = await lock.acquire(token=b"mine")
    acquired_by_another = await another_lock.acquire(token=b"another")

    assert acquired
    assert not acquired_by_another


def test_the_grant_lock_outlasts_a_refresh_and_its_redis_commands():
    redis_commands = 4 * store_module.REDIS_COMMAND_TIMEOUT
    refresh_and_redis_commands = provider_module.REFRESH_TIMEOUT + redis_commands

    assert provider_module.REFRESH_TIMEOUT >= 10
    assert refresh_and_redis_commands <= store_module.LOCK_TIMEOUT


async def test_a_refresh_lock_held_too_long_is_a_retryable_tool_error(provider, monkeypatch):
    monkeypatch.setattr(store_module, "LOCK_WAIT", 0.1)
    access = await add_grant(provider, EXPIRING)

    async with signed_in(provider, access), provider.store.lock("grant", "grant"):
        with pytest.raises(ToolError, match=BUSY):
            await enter_lightdash(provider)


@respx.mock
async def test_token_expiring_during_a_call_is_refreshed(provider):
    access = await add_grant(provider, FRESH)
    answers = [
        httpx.Response(401),
        httpx.Response(200, json={"results": {"name": "Org"}}),
    ]

    async with signed_in(provider, access):
        respx.post(TOKEN_URL).mock(return_value=token_response())
        org = respx.get(ORG_URL).mock(side_effect=answers)

        result = await get_org(provider)

        retried = org.calls[1].request
        loaded = await provider.load_access_token(access)
        assert result == {"name": "Org"}
        assert retried.headers["Authorization"] == "Bearer ld-access-2"
        assert loaded is not None


@respx.mock
async def test_refused_refresh_during_a_call_ends_the_sign_in(provider):
    access = await add_grant(provider, FRESH)
    refused = httpx.Response(400, json={"error": "invalid_grant"})

    async with signed_in(provider, access):
        respx.post(TOKEN_URL).mock(return_value=refused)
        respx.get(ORG_URL).mock(return_value=httpx.Response(401))

        with pytest.raises(ToolError, match=RECONNECT):
            await get_org(provider)

        loaded = await provider.load_access_token(access)
        assert loaded is None


async def test_tools_require_a_sign_in(provider):
    with pytest.raises(ToolError, match="Not signed in"):
        await enter_lightdash(provider)


async def test_grants_stay_separate(provider):
    first = await add_grant(provider, FRESH, "first")
    second = await add_grant(provider, FRESH, "second")

    await provider.end_grant("first", "test")

    ended = await provider.load_access_token(first)
    kept = await provider.load_access_token(second)
    token = await provider.lightdash_token("second")
    assert ended is None
    assert kept.grant_id == "second"
    assert token == "ld-access-second"


@respx.mock
async def test_refresh_token_survives_lightdash_being_down(provider):
    await add_grant(provider, FRESH)
    refresh = await refresh_of(provider)
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
    unreachable = "Couldn't reach Lightdash to refresh your sign-in. Try again in a moment."

    with pytest.raises(TokenError) as error:
        await provider.exchange_refresh_token(CLIENT, refresh, [])

    kept = await refresh_of(provider)
    assert error.value.error == "invalid_request"
    assert error.value.error_description == unreachable
    assert kept == refresh

    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    token = await provider.exchange_refresh_token(CLIENT, refresh, [])

    new_access = await provider.load_access_token(token.access_token)
    new_refresh = await provider.load_refresh_token(CLIENT, token.refresh_token)
    old_refresh = await provider.store.get("refresh", digest(refresh.token), Refresh)
    assert new_access
    assert new_refresh
    assert old_refresh is None


@respx.mock
async def test_a_cancelled_refresh_keeps_the_old_tokens(provider):
    access = await add_grant(provider, FRESH)
    refresh = await refresh_of(provider)
    calling = asyncio.Event()

    async def hang(request):
        calling.set()
        await asyncio.sleep(10)

    respx.post(TOKEN_URL).mock(side_effect=hang)
    exchange = asyncio.create_task(provider.exchange_refresh_token(CLIENT, refresh, []))
    await calling.wait()

    exchange.cancel()

    with pytest.raises(asyncio.CancelledError):
        await exchange

    loaded = await provider.load_access_token(access)
    kept = await refresh_of(provider)
    is_locked = await is_grant_locked(provider)
    assert loaded
    assert kept == refresh
    assert not is_locked

    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    issued = await provider.exchange_refresh_token(CLIENT, refresh, [])

    assert issued


@respx.mock
async def test_new_tokens_are_written_together(provider, monkeypatch):
    access = await add_grant(provider, FRESH)
    refresh = await refresh_of(provider)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    redis = provider.store._redis
    original = redis.pipeline

    def failing_execute(*args, **kwargs):
        raise ConnectionError("Redis went away")

    def failing_pipeline(*args, **kwargs):
        pipeline = original(*args, **kwargs)
        pipeline.execute = failing_execute
        return pipeline

    monkeypatch.setattr(redis, "pipeline", failing_pipeline)

    with pytest.raises(ConnectionError):
        await provider.exchange_refresh_token(CLIENT, refresh, [])

    monkeypatch.undo()

    # Nothing was written: the client's tokens still work, so it isn't locked out.
    loaded = await provider.load_access_token(access)
    kept = await refresh_of(provider)
    assert loaded
    assert kept == refresh


@respx.mock
async def test_revoke_during_a_refresh_exchange_ends_the_new_tokens(provider):
    await add_grant(provider, FRESH)
    refresh = await refresh_of(provider)
    refreshing = asyncio.Event()
    finish = asyncio.Event()

    async def slow_refresh(request):
        refreshing.set()
        await finish.wait()
        return REFRESHED

    async def revoke_like_the_sdk():
        # As the SDK's /revoke does: load the token, then revoke it.
        token = await provider.load_refresh_token(CLIENT, refresh.token)
        assert token
        await provider.revoke_token(token)

    respx.post(TOKEN_URL).mock(side_effect=slow_refresh)
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    exchange = asyncio.create_task(provider.exchange_refresh_token(CLIENT, refresh, []))
    await refreshing.wait()

    revoked = asyncio.create_task(revoke_like_the_sdk())
    await asyncio.sleep(0.05)
    finish.set()
    issued, _ = await asyncio.gather(exchange, revoked)

    grant = await grant_of(provider)
    loaded = await provider.load_access_token(issued.access_token)
    assert grant is None
    assert loaded is None


@respx.mock
async def test_server_side_refresh_errors_keep_the_sign_in(provider):
    access = await add_grant(provider, EXPIRING)
    refused = httpx.Response(401, json={"error": "invalid_client"})
    respx.post(TOKEN_URL).mock(return_value=refused)

    with pytest.raises(RefreshFailed, match="Lightdash error 401"):
        await provider.lightdash_token("grant")

    loaded = await provider.load_access_token(access)
    assert loaded


@respx.mock
async def test_requests_refused_with_the_same_token_refresh_it_once(provider):
    await add_grant(provider, FRESH)
    route = respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    requests = [provider.lightdash_token("grant", "ld-access-grant") for _ in range(5)]

    tokens = await asyncio.gather(*requests)

    assert tokens == ["ld-access-2"] * 5
    assert route.call_count == 1

    # Refused with the new token: refreshed again.
    third = {"access_token": "ld-access-3", "refresh_token": "r3"}
    route.mock(return_value=httpx.Response(200, json=third))

    token = await provider.lightdash_token("grant", "ld-access-2")

    assert token == "ld-access-3"


@respx.mock
async def test_revoke_waits_for_a_refresh_in_flight(provider):
    access = await add_grant(provider, EXPIRING)
    refreshing = asyncio.Event()
    finish = asyncio.Event()

    async def slow_refresh(request):
        refreshing.set()
        await finish.wait()
        return token_response()

    respx.post(TOKEN_URL).mock(side_effect=slow_refresh)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    refresh = asyncio.create_task(provider.lightdash_token("grant"))
    await refreshing.wait()

    token = await provider.load_access_token(access)
    revoked = asyncio.create_task(provider.revoke_token(token))
    await asyncio.sleep(0.05)
    finish.set()
    await asyncio.gather(refresh, revoked)

    grant = await grant_of(provider)
    assert grant is None
    assert b"token=ld-refresh-2" in revoke.calls[0].request.content


@respx.mock
async def test_failed_callback_returns_to_the_client(provider):
    await provider.store.put("transaction", "t", approved_transaction("client-state"))
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))

    response = await provider.lightdash_callback(callback_request("t"))

    assert response.status_code == 302
    assert response.headers["location"].startswith(f"{REDIRECT}?error=server_error")


@respx.mock
async def test_slow_refresh_gives_up_before_the_lock_expires(provider, monkeypatch):
    monkeypatch.setattr(provider_module, "REFRESH_TIMEOUT", 0.05)
    access = await add_grant(provider, EXPIRING)

    async def slow_refresh(request):
        await asyncio.sleep(1)
        return token_response()

    respx.post(TOKEN_URL).mock(side_effect=slow_refresh)

    with pytest.raises(RefreshFailed, match="in time"):
        await provider.lightdash_token("grant")

    loaded = await provider.load_access_token(access)
    is_locked = await is_grant_locked(provider)
    assert loaded
    assert not is_locked


@respx.mock
async def test_grant_lasts_once_its_code_is_exchanged(provider):
    redis = provider.store._redis
    user = httpx.Response(200, json={"results": {"userUuid": "user"}})
    await provider.store.put("transaction", "t", approved_transaction(None))
    respx.post(TOKEN_URL).mock(return_value=token_response("ld-access", "ld-refresh"))
    respx.get(USER_URL).mock(return_value=user)

    response = await provider.lightdash_callback(callback_request("t"))

    location = response.headers["location"]
    issued_code = location.split("code=")[1]
    code = await provider.load_authorization_code(CLIENT, issued_code)
    grant_key = f"lightdash-mcp:grant:{code.grant_id}"
    ttl_before = await redis.ttl(grant_key)
    # A sign-in whose code is never exchanged doesn't keep the Lightdash tokens for long.
    assert 0 < ttl_before <= TRANSACTION_TTL

    await provider.exchange_authorization_code(CLIENT, code)

    ttl_after = await redis.ttl(grant_key)
    assert ttl_after > REFRESH_TTL - 60


async def test_tokens_copied_under_another_key_are_refused(provider):
    access = await add_grant(provider, FRESH)
    redis = provider.store._redis
    forged = digest("forged")
    refresh_key = f"lightdash-mcp:refresh:{digest('our-refresh-grant')}"
    access_key = f"lightdash-mcp:access:{digest(access)}"

    await redis.copy(refresh_key, f"lightdash-mcp:refresh:{forged}")
    await redis.copy(access_key, f"lightdash-mcp:access:{forged}")

    original_refresh = await provider.load_refresh_token(CLIENT, "our-refresh-grant")
    forged_refresh = await provider.load_refresh_token(CLIENT, "forged")
    forged_access = await provider.load_access_token("forged")
    assert original_refresh
    assert forged_refresh is None
    assert forged_access is None


@respx.mock
async def test_a_grant_copied_over_another_is_refused(provider):
    # Someone who can write to Redis copies the victim's grant over their own: their tokens must
    # not reach it.
    await add_grant(provider, FRESH, "victim", subject="victim")
    attacker = await add_grant(provider, FRESH, "attacker", subject="attacker")
    redis = provider.store._redis
    await redis.copy("lightdash-mcp:grant:victim", "lightdash-mcp:grant:attacker", replace=True)
    route = respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    access = await provider.load_access_token(attacker)
    refresh = await provider.load_refresh_token(CLIENT, "our-refresh-attacker")

    assert access is None
    assert refresh is None

    with pytest.raises(SignInRequired):
        await provider.lightdash_token("attacker")

    assert route.call_count == 0


async def test_a_refresh_token_is_valid_only_while_its_grant_points_to_it(provider):
    await add_grant(provider, FRESH)
    grant = await grant_of(provider)
    elsewhere = grant.model_copy(update={"refresh_digest": digest("another")})

    await provider.store.put("grant", "grant", elsewhere)

    refresh = await provider.load_refresh_token(CLIENT, "our-refresh-grant")
    assert refresh is None


async def test_records_from_an_older_version_count_as_missing(provider):
    another_model = Refresh(token="t", client_id="c", scopes=[], grant_id="g")
    await provider.store.put("grant", "grant", another_model)

    grant = await grant_of(provider)

    assert grant is None

    raw = provider.store._fernet.encrypt(b'{"client_id": "client"}')
    await provider.store._redis.set("lightdash-mcp:grant:old", raw)

    old = await grant_of(provider, "old")

    assert old is None


@respx.mock
async def test_a_refresh_token_used_twice_ends_the_sign_in(provider, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    await add_grant(provider, FRESH)
    refresh = await refresh_of(provider)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

    issued = await provider.exchange_refresh_token(CLIENT, refresh, [])

    loaded = await provider.load_access_token(issued.access_token)
    assert loaded

    # Another client presenting it is refused, and changes nothing.
    other = OAuthClientInformationFull(client_id="other", redirect_uris=[REDIRECT])
    presented_by_other = await provider.load_refresh_token(other, refresh.token)
    still_loaded = await provider.load_access_token(issued.access_token)
    assert presented_by_other is None
    assert still_loaded

    reused = await provider.load_refresh_token(CLIENT, refresh.token)
    access_after_reuse = await provider.load_access_token(issued.access_token)
    refresh_after_reuse = await provider.load_refresh_token(CLIENT, issued.refresh_token)
    assert reused is None
    assert access_after_reuse is None
    assert refresh_after_reuse is None
    assert b"token=ld-refresh-2" in revoke.calls[0].request.content
    assert '"reason": "refresh_token_reused"' in caplog.text


@respx.mock
async def test_sign_ins_end_after_their_lifetime(provider):
    await add_grant(provider, FRESH)
    grant = await grant_of(provider)
    almost_over = grant.model_copy(update={"created_at": time.time() - GRANT_LIFETIME + 100})
    await provider.store.put("grant", "grant", almost_over)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    refresh = await refresh_of(provider)

    issued = await provider.exchange_refresh_token(CLIENT, refresh, [])

    keys = [
        "grant:grant",
        f"refresh:{digest(issued.refresh_token)}",
        f"access:{digest(issued.access_token)}",
    ]
    assert issued.expires_in <= 100

    for key in keys:
        ttl = await provider.store._redis.ttl(f"lightdash-mcp:{key}")

        assert 0 < ttl <= 100


@respx.mock
async def test_clients_expire_unless_they_get_tokens(provider):
    client = CLIENT.model_copy(update={"client_name": "App"})
    redis = provider.store._redis
    key = "lightdash-mcp:client:client"

    await provider.register_client(client)

    registered_ttl = await redis.ttl(key)
    assert 0 < registered_ttl <= CLIENT_TTL

    await redis.expire(key, 60)

    # Anyone can look a client up through /authorize: that doesn't keep it.
    found = await provider.get_client("client")
    looked_up_ttl = await redis.ttl(key)
    assert found
    assert looked_up_ttl <= 60

    await add_grant(provider, FRESH)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    refresh = await refresh_of(provider)

    await provider.exchange_refresh_token(client, refresh, [])

    refreshed_ttl = await redis.ttl(key)
    assert refreshed_ttl > 60


@respx.mock
async def test_the_shared_http_client_keeps_no_cookies(provider):
    set_cookie = {"Set-Cookie": "connect.sid=user-a-session; Path=/"}
    with_cookie = httpx.Response(200, json={}, headers=set_cookie)
    first = respx.get(USER_URL).mock(return_value=with_cookie)

    await provider.http.get("/api/v1/user", headers={"Authorization": "Bearer user-a"})
    await provider.http.get("/api/v1/user", headers={"Authorization": "Bearer user-b"})

    assert "cookie" not in first.calls[1].request.headers
    assert not provider.http.cookies


async def consent_page(provider: LightdashOAuthProvider, redirect_uri: str) -> tuple[str, str]:
    client = OAuthClientInformationFull(
        client_id="client",
        client_name="App",
        redirect_uris=[redirect_uri],
    )
    params = AuthorizationParams(
        state=None,
        scopes=[],
        code_challenge="x" * 43,
        redirect_uri=redirect_uri,
        redirect_uri_provided_explicitly=True,
    )

    await provider.register_client(client)
    location = await provider.authorize(client, params)
    query = location.split("?", 1)[1].encode()
    response = await provider.consent_page(consent_request(query))

    body = response.body.decode()
    cookie = response.headers["set-cookie"]

    return body, cookie


async def test_consent_page_shows_where_the_user_returns(provider):
    loopback, _ = await consent_page(provider, "http://localhost:9999/callback?next=1")

    assert "<code>http://localhost:9999/callback?next=1</code>" in loopback
    assert 'class="warning"' not in loopback

    app, _ = await consent_page(provider, "myapp://oauth/done")

    assert "<code>myapp://oauth/done</code>" in app
    assert "opens an app" in app

    unlisted, _ = await consent_page(provider, "https://dex.example.com/callback")

    assert "<code>https://dex.example.com/callback</code>" in unlisted
    assert "whoever runs dex.example.com" in unlisted

    provider.settings.redirect_hosts = ["dex.example.com"]
    listed, _ = await consent_page(provider, "https://dex.example.com/callback")

    assert 'class="warning"' not in listed


async def test_approved_consent_cannot_be_reopened_in_another_browser(provider):
    await consent_page(provider, REDIRECT)
    keys = await provider.store._redis.keys("lightdash-mcp:transaction:*")
    transaction_id = keys[0].decode().rsplit(":", 1)[1]
    transaction = await provider.store.get("transaction", transaction_id, Transaction)
    transaction.approved = True
    await provider.store.put("transaction", transaction_id, transaction)
    query = f"transaction={transaction_id}".encode()

    response = await provider.consent_page(consent_request(query))

    stored = await provider.store.get("transaction", transaction_id, Transaction)
    assert response.status_code == 400
    assert "set-cookie" not in response.headers
    assert stored.csrf == transaction.csrf


async def test_consent_cookie_is_secure_behind_an_https_public_url(provider):
    _, cookie = await consent_page(provider, REDIRECT)

    assert "secure" not in cookie.lower()

    provider.settings.public_url = "https://mcp.example.com"
    _, cookie = await consent_page(provider, REDIRECT)

    assert "secure" in cookie.lower()


async def test_issued_access_tokens_follow_the_configured_lifetime(provider):
    a_day = 24 * 60 * 60
    almost_a_day = 23 * 60 * 60
    provider.settings.access_token_ttl = a_day
    await add_grant(provider, FRESH)
    grant = await grant_of(provider)

    issued = await provider._issue("grant", grant, [], None)

    access = await provider.load_access_token(issued.access_token)
    ttl = await provider.store._redis.ttl(f"lightdash-mcp:access:{digest(issued.access_token)}")
    assert issued.expires_in == a_day
    assert access.expires_at - time.time() > almost_a_day
    assert ttl > almost_a_day


async def test_a_code_is_valid_only_while_its_grant_points_to_it(provider):
    code = await add_code(provider.settings, provider.store._redis, CLIENT_FIELDS)

    loaded = await provider.load_authorization_code(CLIENT, code)

    assert loaded

    grant = await grant_of(provider)
    replaced = grant.model_copy(update={"code_digest": digest("another")})
    await provider.store.put("grant", "grant", replaced)

    after_replacement = await provider.load_authorization_code(CLIENT, code)

    assert after_replacement is None

    await provider.store.delete("grant", "grant")

    after_deletion = await provider.load_authorization_code(CLIENT, code)

    assert after_deletion is None


async def test_a_code_exchange_fails_once_its_sign_in_ended(provider):
    redis = provider.store._redis
    replaced = await add_code(provider.settings, redis, CLIENT_FIELDS, "replaced")
    ended = await add_code(provider.settings, redis, CLIENT_FIELDS, "ended")
    replaced_code = await provider.load_authorization_code(CLIENT, replaced)
    ended_code = await provider.load_authorization_code(CLIENT, ended)
    codes = [replaced_code, ended_code]

    grant = await grant_of(provider, "replaced")
    other = grant.model_copy(update={"code_digest": digest("another")})
    await provider.store.put("grant", "replaced", other)
    await provider.end_grant("ended", "test")

    for code in codes:
        with pytest.raises(TokenError) as error:
            await provider.exchange_authorization_code(CLIENT, code)

        assert error.value.error == "invalid_grant"
        assert error.value.error_description == "Sign-in ended"


@respx.mock
async def test_a_refresh_token_exchanged_twice_at_once_works_once(provider):
    await add_grant(provider, FRESH)
    refresh = await refresh_of(provider)
    route = respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    results = await asyncio.gather(
        provider.exchange_refresh_token(CLIENT, refresh, []),
        provider.exchange_refresh_token(CLIENT, refresh, []),
        return_exceptions=True,
    )

    [issued] = [result for result in results if isinstance(result, OAuthToken)]
    [refused] = [result for result in results if isinstance(result, TokenError)]
    access = await provider.load_access_token(issued.access_token)
    new_refresh = await provider.load_refresh_token(CLIENT, issued.refresh_token)
    assert refused.error == "invalid_grant"
    assert route.call_count == 1
    assert access
    assert new_refresh


async def expire_grant(provider: LightdashOAuthProvider) -> None:
    """Puts the grant past its lifetime while Redis still holds it, as its TTL's rounding can."""
    grant = await grant_of(provider)
    expired = grant.model_copy(update={"created_at": time.time() - GRANT_LIFETIME - 10})

    await provider.store.put("grant", "grant", expired)


@respx.mock
async def test_a_sign_in_past_its_lifetime_gets_no_new_tokens(provider):
    await add_grant(provider, FRESH)
    refresh = await refresh_of(provider)
    await expire_grant(provider)
    lightdash_refresh = respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    with pytest.raises(TokenError) as error:
        await provider.exchange_refresh_token(CLIENT, refresh, [])

    grant = await grant_of(provider)
    assert error.value.error == "invalid_grant"
    assert not lightdash_refresh.called
    assert grant is None


@respx.mock
async def test_tools_past_the_sign_in_lifetime_ask_to_reconnect(provider):
    await add_grant(provider, EXPIRING)
    await expire_grant(provider)
    lightdash_refresh = respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    with pytest.raises(SignInRequired):
        await provider.lightdash_token("grant")

    grant = await grant_of(provider)
    assert not lightdash_refresh.called
    assert grant is None


async def test_an_expired_access_token_is_refused_while_redis_still_holds_it(provider):
    access = await add_grant(provider, FRESH)
    stored = await provider.store.get("access", digest(access), Access)
    expired = stored.model_copy(update={"expires_at": int(time.time()) - 10})

    await provider.store.put("access", digest(access), expired)

    held = await provider.store.get("access", digest(access), Access)
    loaded = await provider.load_access_token(access)
    assert held
    assert loaded is None


@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(400, text="<html>Bad request</html>"),
        httpx.Response(400, json=[{"error": "invalid_grant"}]),
        httpx.Response(500, json={"error": "invalid_grant"}),
    ],
)
@respx.mock
async def test_refresh_errors_other_than_a_refused_grant_keep_the_sign_in(provider, answer):
    access = await add_grant(provider, EXPIRING)
    respx.post(TOKEN_URL).mock(return_value=answer)

    with pytest.raises(RefreshFailed):
        await provider.lightdash_token("grant")

    grant = await grant_of(provider)
    loaded = await provider.load_access_token(access)
    assert grant
    assert loaded


@respx.mock
async def test_an_unreachable_upstream_revocation_is_logged(provider, caplog):
    access = await add_grant(provider, FRESH)
    respx.post(REVOKE_URL).mock(side_effect=httpx.ConnectError("down"))

    await revoke_access(provider, access)

    grant = await grant_of(provider)
    assert grant is None
    assert '"event": "lightdash_revoke_failed"' in caplog.text
    assert '"failure": "ConnectError"' in caplog.text


@pytest.mark.parametrize("ttl", [0, -5])
async def test_a_ttl_already_past_keeps_the_value_for_one_second(provider, ttl):
    value = Rotated(client_id="client", grant_id="grant")
    redis = provider.store._redis

    await provider.store.put("rotated", "put", value, ttl)
    await provider.store.write(put=[("rotated", "written", value, ttl)])

    put_ttl = await redis.ttl("lightdash-mcp:rotated:put")
    written_ttl = await redis.ttl("lightdash-mcp:rotated:written")
    assert put_ttl == 1
    assert written_ttl == 1


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (httpx.Response(404, json={"error": {"message": "No such org"}}), "Not found: No such org"),
        (httpx.Response(500, json={"error": {"message": "Boom"}}), "Lightdash error 500: Boom"),
        (httpx.ConnectError("down"), UNREACHABLE),
    ],
)
@respx.mock
async def test_tools_map_other_lightdash_failures(provider, answer, message):
    access = await add_grant(provider, FRESH)
    respx.get(ORG_URL).mock(side_effect=[answer])

    async with signed_in(provider, access):
        with pytest.raises(ToolError, match=re.escape(message)):
            await get_org(provider)
