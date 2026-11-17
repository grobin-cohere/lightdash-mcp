import asyncio
import json
import logging
import time

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AuthorizationParams, TokenError
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.auth import OAuthClientInformationFull
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
    SignInRequired,
    Transaction,
    _consent_cookie,
)
from lightdash_mcp.auth.store import Store, digest
from lightdash_mcp.config import Settings
from lightdash_mcp.tools.common import BUSY, RECONNECT, lightdash

LIGHTDASH = "http://lightdash.test"
TOKEN_URL = f"{LIGHTDASH}/api/v1/oauth/token"
REVOKE_URL = f"{LIGHTDASH}/api/v1/oauth/revoke"
CLIENT = OAuthClientInformationFull(client_id="client", redirect_uris=["http://localhost:9999/callback"])
REFRESHED = httpx.Response(200, json={"access_token": "ld-access-2", "refresh_token": "ld-refresh-2", "expires_in": 3600})


@pytest.fixture
def provider() -> LightdashOAuthProvider:
    settings = Settings(
        _env_file=None,
        lightdash_url=LIGHTDASH,
        lightdash_client_id="id",
        lightdash_client_secret="secret",
        fernet_key=Fernet.generate_key().decode(),
    )
    return LightdashOAuthProvider(settings, Store(FakeAsyncRedis(), settings.fernet_key))


async def add_grant(provider: LightdashOAuthProvider, expires_in: float, grant_id: str = "grant", subject: str = "user") -> str:
    """A grant with an access token and a refresh token, both named after it. Returns the access token."""
    access, refresh = f"our-access-{grant_id}", f"our-refresh-{grant_id}"
    grant = Grant(
        client_id="client",
        subject=subject,
        access_token=f"ld-access-{grant_id}",
        refresh_token=f"ld-refresh-{grant_id}",
        expires_at=time.time() + expires_in,
        access_digest=digest(access),
        refresh_digest=digest(refresh),
    )
    common = {"client_id": "client", "scopes": [], "subject": subject, "grant_id": grant_id}
    await provider.store.put("grant", grant_id, grant)
    await provider.store.put("access", digest(access), Access(token=access, **common))
    await provider.store.put("refresh", digest(refresh), Refresh(token=refresh, expires_at=int(time.time()) + 600, **common))
    return access


async def refresh_of(provider: LightdashOAuthProvider, grant_id: str = "grant") -> Refresh:
    return await provider.load_refresh_token(CLIENT, f"our-refresh-{grant_id}")


def signed_in_as(access: Access):
    return auth_context_var.set(AuthenticatedUser(access))


async def test_stored_values_are_encrypted(provider):
    await add_grant(provider, 3600)
    raw = await provider.store._redis.get("lightdash-mcp:grant:grant")
    assert b"ld-refresh" not in raw


async def test_values_from_another_key_count_as_missing(provider):
    access = await add_grant(provider, 3600)
    other = Store(provider.store._redis, Fernet.generate_key().decode())
    assert await other.get("access", digest(access), Access) is None
    assert await other.pop("grant", "grant", Grant) is None


async def test_fresh_token_is_used_as_is(provider):
    await add_grant(provider, 3600)
    assert await provider.lightdash_token("grant") == "ld-access-grant"


@respx.mock
async def test_concurrent_requests_refresh_once(provider):
    await add_grant(provider, 10)
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200, json={"access_token": "ld-access-2", "refresh_token": "ld-refresh-2", "expires_in": 3600}
        )
    )
    tokens = await asyncio.gather(*(provider.lightdash_token("grant") for _ in range(5)))
    assert tokens == ["ld-access-2"] * 5
    assert route.call_count == 1
    assert b"refresh_token=ld-refresh-grant" in route.calls[0].request.content
    grant = await provider.store.get("grant", "grant", Grant)
    assert grant.refresh_token == "ld-refresh-2"


@respx.mock
async def test_refused_refresh_ends_the_sign_in(provider):
    access = await add_grant(provider, 10)
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_grant"}))
    with pytest.raises(SignInRequired):
        await provider.lightdash_token("grant")
    assert await provider.store.get("grant", "grant", Grant) is None
    assert await provider.load_access_token(access) is None


async def test_access_token_is_tied_to_its_grant(provider):
    access = await add_grant(provider, 3600)
    assert (await provider.load_access_token(access)).subject == "user"
    await provider.end_grant("grant", "test")
    assert await provider.load_access_token(access) is None


@respx.mock
async def test_revoke_ends_the_grant_upstream_too(provider, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    access = await add_grant(provider, 3600)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    await provider.revoke_token(await provider.load_access_token(access))
    assert await provider.load_access_token(access) is None
    sent = dict(httpx.QueryParams(revoke.calls[0].request.content.decode()))
    # Lightdash's client credentials, as RFC 7009 asks of a confidential client.
    assert sent == {"token": "ld-refresh-grant", "token_type_hint": "refresh_token", "client_id": "id", "client_secret": "secret"}
    assert "lightdash_revoke_failed" not in caplog.text


async def test_a_second_revocation_of_an_ended_grant_logs_nothing(provider, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    token = await provider.load_access_token(await add_grant(provider, 3600))
    await provider.end_grant("grant", "test")
    await provider.revoke_token(token)
    assert audit_events(caplog) == ["grant_ended"]


@respx.mock
async def test_a_revocation_that_outlasts_its_lock_still_finishes(provider, caplog, monkeypatch):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    token = await provider.load_access_token(await add_grant(provider, 3600))
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

    async def expired(self):
        raise LockNotOwnedError("Cannot release a lock that's no longer owned")

    monkeypatch.setattr(Lock, "release", expired)
    await provider.revoke_token(token)
    assert audit_events(caplog) == ["token_revoked", "grant_ended"]
    assert await provider.load_access_token(token.token) is None
    assert revoke.called


def audit_events(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [json.loads(r.getMessage())["event"] for r in caplog.records if r.name == "lightdash_mcp.audit"]


@respx.mock
async def test_refused_upstream_revocation_is_logged(provider, caplog):
    access = await add_grant(provider, 3600)
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_client"}))
    await provider.revoke_token(await provider.load_access_token(access))
    assert await provider.load_access_token(access) is None
    assert '"event": "lightdash_revoke_failed"' in caplog.text and '"failure": 401' in caplog.text


@respx.mock
async def test_tools_map_lightdash_errors(provider):
    access = await add_grant(provider, 3600)
    reset = signed_in_as(await provider.load_access_token(access))
    try:
        respx.get(f"{LIGHTDASH}/api/v1/org").mock(
            return_value=httpx.Response(403, json={"status": "error", "error": {"message": "Not allowed"}})
        )
        with pytest.raises(ToolError, match="Permission denied.*Not allowed"):
            async with lightdash(provider) as ld:
                await ld.get("/api/v1/org")

        # Still refused with a refreshed token: Lightdash renewed the sign-in, so the 401 is about something else,
        # such as an Enterprise-only route or a proxy. The sign-in stays.
        respx.post(TOKEN_URL).mock(return_value=REFRESHED)
        respx.get(f"{LIGHTDASH}/api/v1/org").mock(return_value=httpx.Response(401, json={"error": {"message": "No"}}))
        with pytest.raises(ToolError, match=r"Lightdash refused this request \(401\): No"):
            async with lightdash(provider) as ld:
                await ld.get("/api/v1/org")
        assert await provider.load_access_token(access)
        assert (await provider.store.get("grant", "grant", Grant)).access_token == "ld-access-2"
    finally:
        auth_context_var.reset(reset)


@respx.mock
async def test_refresh_errors_read_the_same_before_and_during_a_call(provider):
    access = await add_grant(provider, 3600)
    reset = signed_in_as(await provider.load_access_token(access))
    try:
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(503))
        respx.get(f"{LIGHTDASH}/api/v1/org").mock(return_value=httpx.Response(401))
        with pytest.raises(ToolError, match="Lightdash error 503 while refreshing your sign-in. Try again"):
            async with lightdash(provider) as ld:
                await ld.get("/api/v1/org")

        await provider.store.put(
            "grant", "grant", (await provider.store.get("grant", "grant", Grant)).model_copy(update={"expires_at": 0})
        )
        with pytest.raises(ToolError, match="Lightdash error 503 while refreshing your sign-in. Try again"):
            async with lightdash(provider):
                pass
        assert await provider.load_access_token(access)
    finally:
        auth_context_var.reset(reset)


@respx.mock
async def test_malformed_refresh_answer_is_a_retryable_tool_error(provider):
    access = await add_grant(provider, 10)
    reset = signed_in_as(await provider.load_access_token(access))
    try:
        for answer in (
            httpx.Response(200, json={"access_token": "only"}),
            httpx.Response(200, text="<html>"),
            httpx.Response(200, json=[1]),
        ):
            respx.post(TOKEN_URL).mock(return_value=answer)
            with pytest.raises(ToolError, match="no token. Try again in a moment"):
                async with lightdash(provider):
                    pass
        assert (await provider.store.get("grant", "grant", Grant)).refresh_token == "ld-refresh-grant"
    finally:
        auth_context_var.reset(reset)


async def test_a_lock_finds_its_own_token_after_a_lost_answer(provider, monkeypatch):
    monkeypatch.setattr(store_module, "LOCK_WAIT", 0.1)
    lock = provider.store.lock("grant", "grant")
    # As a SET NX that Redis applied, but whose answer was lost, leaves it for the retry.
    await lock.redis.set(lock.name, b"mine", px=60_000)
    assert await lock.acquire(token=b"mine")
    assert not await provider.store.lock("grant", "grant").acquire(token=b"another")


def test_the_grant_lock_outlasts_a_refresh_and_its_redis_commands():
    assert provider_module.REFRESH_TIMEOUT >= 10
    assert provider_module.REFRESH_TIMEOUT + 4 * store_module.REDIS_COMMAND_TIMEOUT <= store_module.LOCK_TIMEOUT


async def test_a_refresh_lock_held_too_long_is_a_retryable_tool_error(provider, monkeypatch):
    monkeypatch.setattr(store_module, "LOCK_WAIT", 0.1)
    access = await add_grant(provider, 10)
    reset = signed_in_as(await provider.load_access_token(access))
    try:
        async with provider.store.lock("grant", "grant"):
            with pytest.raises(ToolError, match=BUSY):
                async with lightdash(provider):
                    pass
    finally:
        auth_context_var.reset(reset)


@respx.mock
async def test_token_expiring_during_a_call_is_refreshed(provider):
    access = await add_grant(provider, 3600)
    reset = signed_in_as(await provider.load_access_token(access))
    try:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200, json={"access_token": "ld-access-2", "refresh_token": "ld-refresh-2", "expires_in": 3600}
            )
        )
        org = respx.get(f"{LIGHTDASH}/api/v1/org").mock(
            side_effect=[httpx.Response(401), httpx.Response(200, json={"results": {"name": "Org"}})]
        )
        async with lightdash(provider) as ld:
            assert await ld.get("/api/v1/org") == {"name": "Org"}
        assert org.calls[1].request.headers["Authorization"] == "Bearer ld-access-2"
        assert await provider.load_access_token(access) is not None
    finally:
        auth_context_var.reset(reset)


@respx.mock
async def test_refused_refresh_during_a_call_ends_the_sign_in(provider):
    access = await add_grant(provider, 3600)
    reset = signed_in_as(await provider.load_access_token(access))
    try:
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(400, json={"error": "invalid_grant"}))
        respx.get(f"{LIGHTDASH}/api/v1/org").mock(return_value=httpx.Response(401))
        with pytest.raises(ToolError, match=RECONNECT):
            async with lightdash(provider) as ld:
                await ld.get("/api/v1/org")
        assert await provider.load_access_token(access) is None
    finally:
        auth_context_var.reset(reset)


async def test_tools_require_a_sign_in(provider):
    with pytest.raises(ToolError, match="Not signed in"):
        async with lightdash(provider):
            pass


async def test_grants_stay_separate(provider):
    first = await add_grant(provider, 3600, "first")
    second = await add_grant(provider, 3600, "second")
    await provider.end_grant("first", "test")
    assert await provider.load_access_token(first) is None
    assert (await provider.load_access_token(second)).grant_id == "second"
    assert await provider.lightdash_token("second") == "ld-access-second"


@respx.mock
async def test_refresh_token_survives_lightdash_being_down(provider):
    await add_grant(provider, 3600)
    refresh = await refresh_of(provider)
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(TokenError) as error:
        await provider.exchange_refresh_token(CLIENT, refresh, [])
    assert error.value.error == "invalid_request"
    assert error.value.error_description == "Couldn't reach Lightdash to refresh your sign-in. Try again in a moment."
    assert await refresh_of(provider) == refresh

    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    token = await provider.exchange_refresh_token(CLIENT, refresh, [])
    assert await provider.load_access_token(token.access_token)
    assert await provider.load_refresh_token(CLIENT, token.refresh_token)
    assert await provider.store.get("refresh", digest(refresh.token), Refresh) is None


@respx.mock
async def test_a_cancelled_refresh_keeps_the_old_tokens(provider):
    access = await add_grant(provider, 3600)
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

    assert await provider.load_access_token(access)
    assert await refresh_of(provider) == refresh
    assert not await provider.store.lock("grant", "grant").locked()
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    assert await provider.exchange_refresh_token(CLIENT, refresh, [])


@respx.mock
async def test_new_tokens_are_written_together(provider, monkeypatch):
    access = await add_grant(provider, 3600)
    refresh = await refresh_of(provider)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    redis = provider.store._redis
    original = redis.pipeline

    def failing_pipeline(*args, **kwargs):
        pipe = original(*args, **kwargs)
        pipe.execute = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("Redis went away"))
        return pipe

    monkeypatch.setattr(redis, "pipeline", failing_pipeline)
    with pytest.raises(ConnectionError):
        await provider.exchange_refresh_token(CLIENT, refresh, [])
    monkeypatch.undo()
    # Nothing was written: the client's tokens still work, so it isn't locked out.
    assert await provider.load_access_token(access)
    assert await refresh_of(provider) == refresh


@respx.mock
async def test_revoke_during_a_refresh_exchange_ends_the_new_tokens(provider):
    await add_grant(provider, 3600)
    refresh = await refresh_of(provider)
    refreshing, finish = asyncio.Event(), asyncio.Event()

    async def slow_refresh(request):
        refreshing.set()
        await finish.wait()
        return REFRESHED

    respx.post(TOKEN_URL).mock(side_effect=slow_refresh)
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    exchange = asyncio.create_task(provider.exchange_refresh_token(CLIENT, refresh, []))
    await refreshing.wait()

    async def revoke():
        # As the SDK's /revoke does: load the token, then revoke it.
        token = await provider.load_refresh_token(CLIENT, refresh.token)
        assert token
        await provider.revoke_token(token)

    revoked = asyncio.create_task(revoke())
    await asyncio.sleep(0.05)
    finish.set()
    issued, _ = await asyncio.gather(exchange, revoked)
    assert await provider.store.get("grant", "grant", Grant) is None
    assert await provider.load_access_token(issued.access_token) is None


@respx.mock
async def test_server_side_refresh_errors_keep_the_sign_in(provider):
    access = await add_grant(provider, 10)
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_client"}))
    with pytest.raises(RefreshFailed, match="Lightdash error 401"):
        await provider.lightdash_token("grant")
    assert await provider.load_access_token(access)


@respx.mock
async def test_requests_refused_with_the_same_token_refresh_it_once(provider):
    await add_grant(provider, 3600)
    route = respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    tokens = await asyncio.gather(*(provider.lightdash_token("grant", "ld-access-grant") for _ in range(5)))
    assert tokens == ["ld-access-2"] * 5
    assert route.call_count == 1
    # Refused with the new token: refreshed again.
    route.mock(return_value=httpx.Response(200, json={"access_token": "ld-access-3", "refresh_token": "r3"}))
    assert await provider.lightdash_token("grant", "ld-access-2") == "ld-access-3"


@respx.mock
async def test_revoke_waits_for_a_refresh_in_flight(provider):
    access = await add_grant(provider, 10)
    refreshing, finish = asyncio.Event(), asyncio.Event()

    async def slow_refresh(request):
        refreshing.set()
        await finish.wait()
        return httpx.Response(200, json={"access_token": "ld-access-2", "refresh_token": "ld-refresh-2", "expires_in": 3600})

    respx.post(TOKEN_URL).mock(side_effect=slow_refresh)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    refresh = asyncio.create_task(provider.lightdash_token("grant"))
    await refreshing.wait()
    revoked = asyncio.create_task(provider.revoke_token(await provider.load_access_token(access)))
    await asyncio.sleep(0.05)
    finish.set()
    await asyncio.gather(refresh, revoked)

    assert await provider.store.get("grant", "grant", Grant) is None
    assert b"token=ld-refresh-2" in revoke.calls[0].request.content


@respx.mock
async def test_failed_callback_returns_to_the_client(provider):
    transaction = Transaction(
        client_id="client",
        params=AuthorizationParams(
            state="client-state",
            scopes=[],
            code_challenge="x" * 43,
            redirect_uri="http://localhost:9999/callback",
            redirect_uri_provided_explicitly=True,
        ),
        verifier="verifier",
        csrf="csrf",
        approved=True,
    )
    await provider.store.put("transaction", "t", transaction)
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/oauth/lightdash/callback",
            "query_string": b"state=t&code=lightdash-code",
            "headers": [(b"cookie", f"{_consent_cookie('t')}=csrf".encode())],
        }
    )
    response = await provider.lightdash_callback(request)
    assert response.status_code == 302
    assert response.headers["location"].startswith("http://localhost:9999/callback?error=server_error")


@respx.mock
async def test_slow_refresh_gives_up_before_the_lock_expires(provider, monkeypatch):
    monkeypatch.setattr(provider_module, "REFRESH_TIMEOUT", 0.05)
    access = await add_grant(provider, 10)

    async def slow_refresh(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={"access_token": "ld-access-2", "refresh_token": "ld-refresh-2", "expires_in": 3600})

    respx.post(TOKEN_URL).mock(side_effect=slow_refresh)
    with pytest.raises(RefreshFailed, match="in time"):
        await provider.lightdash_token("grant")
    assert await provider.load_access_token(access)
    assert not await provider.store.lock("grant", "grant").locked()


@respx.mock
async def test_grant_lasts_once_its_code_is_exchanged(provider):
    client = OAuthClientInformationFull(client_id="client", redirect_uris=["http://localhost:9999/callback"])
    transaction = Transaction(
        client_id="client",
        params=AuthorizationParams(
            state=None,
            scopes=[],
            code_challenge="x" * 43,
            redirect_uri="http://localhost:9999/callback",
            redirect_uri_provided_explicitly=True,
        ),
        verifier="verifier",
        csrf="csrf",
        approved=True,
    )
    await provider.store.put("transaction", "t", transaction)
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "ld-access", "refresh_token": "ld-refresh", "expires_in": 3600})
    )
    respx.get(f"{LIGHTDASH}/api/v1/user").mock(return_value=httpx.Response(200, json={"results": {"userUuid": "user"}}))
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/oauth/lightdash/callback",
            "query_string": b"state=t&code=lightdash-code",
            "headers": [(b"cookie", f"{_consent_cookie('t')}=csrf".encode())],
        }
    )
    response = await provider.lightdash_callback(request)
    code = await provider.load_authorization_code(client, response.headers["location"].split("code=")[1])
    grant_key = f"lightdash-mcp:grant:{code.grant_id}"
    # A sign-in whose code is never exchanged doesn't keep the Lightdash tokens for long.
    assert 0 < await provider.store._redis.ttl(grant_key) <= TRANSACTION_TTL

    await provider.exchange_authorization_code(client, code)
    assert await provider.store._redis.ttl(grant_key) > REFRESH_TTL - 60


async def test_tokens_copied_under_another_key_are_refused(provider):
    access = await add_grant(provider, 3600)
    redis = provider.store._redis
    await redis.copy(f"lightdash-mcp:refresh:{digest('our-refresh-grant')}", f"lightdash-mcp:refresh:{digest('forged')}")
    await redis.copy(f"lightdash-mcp:access:{digest(access)}", f"lightdash-mcp:access:{digest('forged')}")
    assert await provider.load_refresh_token(CLIENT, "our-refresh-grant")
    assert await provider.load_refresh_token(CLIENT, "forged") is None
    assert await provider.load_access_token("forged") is None


@respx.mock
async def test_a_grant_copied_over_another_is_refused(provider):
    # Someone who can write to Redis copies the victim's grant over their own: their tokens must not reach it.
    await add_grant(provider, 3600, "victim", subject="victim")
    attacker = await add_grant(provider, 3600, "attacker", subject="attacker")
    redis = provider.store._redis
    await redis.copy("lightdash-mcp:grant:victim", "lightdash-mcp:grant:attacker", replace=True)
    route = respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    assert await provider.load_access_token(attacker) is None
    assert await provider.load_refresh_token(CLIENT, "our-refresh-attacker") is None
    with pytest.raises(SignInRequired):
        await provider.lightdash_token("attacker")
    assert route.call_count == 0


async def test_a_refresh_token_is_valid_only_while_its_grant_points_to_it(provider):
    await add_grant(provider, 3600)
    grant = await provider.store.get("grant", "grant", Grant)
    await provider.store.put("grant", "grant", grant.model_copy(update={"refresh_digest": digest("another")}))
    assert await provider.load_refresh_token(CLIENT, "our-refresh-grant") is None


async def test_records_from_an_older_version_count_as_missing(provider):
    await provider.store.put("grant", "grant", Refresh(token="t", client_id="c", scopes=[], grant_id="g"))
    assert await provider.store.get("grant", "grant", Grant) is None
    raw = provider.store._fernet.encrypt(b'{"client_id": "client"}')
    await provider.store._redis.set("lightdash-mcp:grant:old", raw)
    assert await provider.store.get("grant", "old", Grant) is None


@respx.mock
async def test_a_refresh_token_used_twice_ends_the_sign_in(provider, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    await add_grant(provider, 3600)
    refresh = await refresh_of(provider)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    issued = await provider.exchange_refresh_token(CLIENT, refresh, [])
    assert await provider.load_access_token(issued.access_token)

    # Another client presenting it is refused, and changes nothing.
    other = OAuthClientInformationFull(client_id="other", redirect_uris=["http://localhost:9999/callback"])
    assert await provider.load_refresh_token(other, refresh.token) is None
    assert await provider.load_access_token(issued.access_token)

    assert await provider.load_refresh_token(CLIENT, refresh.token) is None
    assert await provider.load_access_token(issued.access_token) is None
    assert await provider.load_refresh_token(CLIENT, issued.refresh_token) is None
    assert b"token=ld-refresh-2" in revoke.calls[0].request.content
    assert '"reason": "refresh_token_reused"' in caplog.text


@respx.mock
async def test_sign_ins_end_after_their_lifetime(provider):
    await add_grant(provider, 3600)
    grant = await provider.store.get("grant", "grant", Grant)
    await provider.store.put("grant", "grant", grant.model_copy(update={"created_at": time.time() - GRANT_LIFETIME + 100}))
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    issued = await provider.exchange_refresh_token(CLIENT, await refresh_of(provider), [])
    assert issued.expires_in <= 100
    for key in ("grant:grant", f"refresh:{digest(issued.refresh_token)}", f"access:{digest(issued.access_token)}"):
        assert 0 < await provider.store._redis.ttl(f"lightdash-mcp:{key}") <= 100


@respx.mock
async def test_clients_expire_unless_they_get_tokens(provider):
    client = CLIENT.model_copy(update={"client_name": "App"})
    await provider.register_client(client)
    key = "lightdash-mcp:client:client"
    assert 0 < await provider.store._redis.ttl(key) <= CLIENT_TTL
    await provider.store._redis.expire(key, 60)
    # Anyone can look a client up through /authorize: that doesn't keep it.
    assert await provider.get_client("client")
    assert await provider.store._redis.ttl(key) <= 60

    await add_grant(provider, 3600)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    await provider.exchange_refresh_token(client, await refresh_of(provider), [])
    assert await provider.store._redis.ttl(key) > 60


@respx.mock
async def test_the_shared_http_client_keeps_no_cookies(provider):
    first = respx.get(f"{LIGHTDASH}/api/v1/user").mock(
        return_value=httpx.Response(200, json={}, headers={"Set-Cookie": "connect.sid=user-a-session; Path=/"})
    )
    await provider.http.get("/api/v1/user", headers={"Authorization": "Bearer user-a"})
    await provider.http.get("/api/v1/user", headers={"Authorization": "Bearer user-b"})
    assert "cookie" not in first.calls[1].request.headers
    assert not provider.http.cookies


async def consent_page(provider: LightdashOAuthProvider, redirect_uri: str) -> tuple[str, str]:
    client = OAuthClientInformationFull(client_id="client", client_name="App", redirect_uris=[redirect_uri])
    await provider.register_client(client)
    params = AuthorizationParams(
        state=None, scopes=[], code_challenge="x" * 43, redirect_uri=redirect_uri, redirect_uri_provided_explicitly=True
    )
    location = await provider.authorize(client, params)
    query = location.split("?", 1)[1].encode()
    response = await provider.consent_page(
        Request({"type": "http", "method": "GET", "path": "/oauth/consent", "query_string": query, "headers": []})
    )
    return response.body.decode(), response.headers["set-cookie"]


async def test_consent_page_shows_where_the_user_returns(provider):
    body, _ = await consent_page(provider, "http://localhost:9999/callback?next=1")
    assert "<code>http://localhost:9999/callback?next=1</code>" in body
    assert 'class="warning"' not in body
    body, _ = await consent_page(provider, "myapp://oauth/done")
    assert "<code>myapp://oauth/done</code>" in body and "opens an app" in body
    body, _ = await consent_page(provider, "https://dex.example.com/callback")
    assert "<code>https://dex.example.com/callback</code>" in body and "whoever runs dex.example.com" in body
    provider.settings.redirect_hosts = ["dex.example.com"]
    body, _ = await consent_page(provider, "https://dex.example.com/callback")
    assert 'class="warning"' not in body


async def test_approved_consent_cannot_be_reopened_in_another_browser(provider):
    await consent_page(provider, "http://localhost:9999/callback")
    transaction_id = (await provider.store._redis.keys("lightdash-mcp:transaction:*"))[0].decode().rsplit(":", 1)[1]
    transaction = await provider.store.get("transaction", transaction_id, Transaction)
    transaction.approved = True
    await provider.store.put("transaction", transaction_id, transaction)

    query = f"transaction={transaction_id}".encode()
    response = await provider.consent_page(
        Request({"type": "http", "method": "GET", "path": "/oauth/consent", "query_string": query, "headers": []})
    )
    assert response.status_code == 400
    assert "set-cookie" not in response.headers
    assert (await provider.store.get("transaction", transaction_id, Transaction)).csrf == transaction.csrf


async def test_consent_cookie_is_secure_behind_an_https_public_url(provider):
    _, cookie = await consent_page(provider, "http://localhost:9999/callback")
    assert "secure" not in cookie.lower()
    provider.settings.public_url = "https://mcp.example.com"
    _, cookie = await consent_page(provider, "http://localhost:9999/callback")
    assert "secure" in cookie.lower()


async def test_issued_access_tokens_follow_the_configured_lifetime(provider):
    provider.settings.access_token_ttl = 24 * 60 * 60
    await add_grant(provider, 3600)
    issued = await provider._issue("grant", await provider.store.get("grant", "grant", Grant), [], None)
    assert issued.expires_in == 24 * 60 * 60
    access = await provider.load_access_token(issued.access_token)
    assert access.expires_at - time.time() > 23 * 60 * 60
    assert await provider.store._redis.ttl(f"lightdash-mcp:access:{digest(issued.access_token)}") > 23 * 60 * 60
