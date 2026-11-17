"""The server over HTTP: the SDK's token and revocation endpoints with this provider, body limits,
the audit log."""

import asyncio
import base64
import itertools
import json
import logging
import time
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from fakeredis import FakeAsyncRedis
from mcp.types import CallToolResult
from redis.asyncio.client import Pipeline
from redis.asyncio.lock import Lock
from redis.asyncio.retry import Retry
from redis.exceptions import ConnectionError

from lightdash_mcp import server as server_module
from lightdash_mcp.auth import store as store_module
from lightdash_mcp.auth.audit import MAX_ITEMS, MAX_VALUE, clip_arguments
from lightdash_mcp.auth.provider import CLIENT_TTL, Access, Code, Grant
from lightdash_mcp.auth.store import Store, digest
from lightdash_mcp.config import Settings
from lightdash_mcp.server import (
    BasicAuthClientId,
    _basic_credentials,
    asgi_app,
    audit,
    create_server,
    transport_security,
)

from .conftest import (
    REDIRECT,
    REFRESHED,
    REVOKE_URL,
    TOKEN_LIFETIME,
    TOKEN_URL,
    VERIFIER,
    add_code,
    make_settings,
)

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}


@pytest.fixture
def settings() -> Settings:
    # A secret of its own, so the audit log test can look for it.
    return make_settings(lightdash_client_secret="lightdash-secret")


@pytest.fixture
async def http(settings, redis):
    transport = httpx.ASGITransport(asgi_app(settings, redis))

    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as http:
        yield http


async def register(http: httpx.AsyncClient, auth_method: str = "client_secret_post") -> dict:
    metadata = {
        "client_name": "App",
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": auth_method,
    }

    response = await http.post("/register", json=metadata)

    assert response.status_code == 201, response.text
    return response.json()


def basic(credentials: bytes) -> str:
    return "Basic " + base64.b64encode(credentials).decode()


def basic_for(client: dict) -> str:
    credentials = f"{client['client_id']}:{client['client_secret']}"

    return basic(credentials.encode())


def credentials(client: dict) -> dict:
    return {"client_id": client["client_id"], "client_secret": client["client_secret"]}


def code_form(code: str, verifier: str = VERIFIER) -> dict:
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": verifier,
    }


async def exchange(
    http: httpx.AsyncClient,
    client: dict,
    code: str,
    verifier: str = VERIFIER,
) -> httpx.Response:
    form = code_form(code, verifier) | credentials(client)

    return await http.post("/token", data=form)


async def refresh(http: httpx.AsyncClient, client: dict, refresh_token: str) -> httpx.Response:
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        **credentials(client),
    }

    return await http.post("/token", data=form)


def audit_messages(caplog) -> list[str]:
    records = [record for record in caplog.records if record.name == "lightdash_mcp.audit"]

    return [record.getMessage() for record in records]


def audit_lines(caplog) -> list[dict]:
    return [json.loads(message) for message in audit_messages(caplog)]


def tool_call() -> SimpleNamespace:
    return SimpleNamespace(method="tools/call", params={"name": "list_projects", "arguments": {}})


async def test_a_code_needs_its_verifier_and_works_once(http, settings, redis):
    client = await register(http)
    code = await add_code(settings, redis, client)

    wrong = await exchange(http, client, code, "w" * 64)
    right = await exchange(http, client, code)
    reused = await exchange(http, client, code)

    assert wrong.status_code == 400
    assert wrong.json()["error"] == "invalid_grant"
    assert right.status_code == 200
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"


async def test_a_code_works_for_its_own_client_only(http, settings, redis):
    client = await register(http)
    other = await register(http)
    code = await add_code(settings, redis, client)

    stolen = await exchange(http, other, code)
    exchanged = await exchange(http, client, code)

    assert stolen.status_code == 400
    assert exchanged.status_code == 200


@respx.mock
async def test_a_refresh_token_works_for_its_own_client_only(http, settings, redis):
    client = await register(http)
    other = await register(http)
    code = await add_code(settings, redis, client)
    exchanged = await exchange(http, client, code)
    refresh_token = exchanged.json()["refresh_token"]
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    stolen = await refresh(http, other, refresh_token)
    rotated = await refresh(http, client, refresh_token)

    assert stolen.status_code == 400
    assert stolen.json()["error"] == "invalid_grant"
    assert rotated.status_code == 200, rotated.text


async def test_a_basic_auth_client_can_revoke(http, settings, redis):
    client = await register(http, "client_secret_basic")
    headers = {"Authorization": basic_for(client)}
    code = await add_code(settings, redis, client)

    tokens = await http.post("/token", headers=headers, data=code_form(code))

    assert tokens.status_code == 200, tokens.text

    revocation = {"token": tokens.json()["access_token"]}

    with respx.mock:
        respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
        revoked = await http.post("/revoke", headers=headers, data=revocation)

    store = Store(redis, settings.fernet_key)
    grant = await store.get("grant", "grant", Grant)
    assert revoked.status_code == 200, revoked.text
    assert grant is None


@pytest.fixture
def held_lock(redis, monkeypatch):
    """The lock of grant `grant`, to hold as a request in flight would. Waiting for it gives up
    after 0.1 seconds."""
    monkeypatch.setattr(store_module, "LOCK_WAIT", 0.1)

    return redis.lock("lightdash-mcp:lock:grant:grant", timeout=60)


async def sign_in(
    http: httpx.AsyncClient,
    settings: Settings,
    redis: FakeAsyncRedis,
    grant_id: str = "grant",
) -> tuple[dict, dict]:
    """A registered client, and the tokens its finished sign-in got."""
    client = await register(http)
    code = await add_code(settings, redis, client, grant_id)
    exchanged = await exchange(http, client, code)

    return client, exchanged.json()


async def stored_grant(
    settings: Settings,
    redis: FakeAsyncRedis,
    grant_id: str = "grant",
) -> Grant | None:
    store = Store(redis, settings.fernet_key)

    return await store.get("grant", grant_id, Grant)


def revocation_form(client: dict, token: str) -> dict:
    return {"token": token, **credentials(client)}


def retryable(response: httpx.Response) -> bool:
    """An OAuth error that tells the client to try again with the same code or refresh token,
    which still work."""
    body = response.json()
    is_a_retry_error = body["error"] == "invalid_request"
    asks_to_try_again = is_a_retry_error and "Try again" in body["error_description"]
    is_not_cached = response.headers["cache-control"] == "no-store"

    return response.status_code == 400 and asks_to_try_again and is_not_cached


@pytest.mark.parametrize(
    "answer",
    [
        httpx.ConnectError("down"),
        httpx.ReadTimeout("slow"),
        httpx.Response(502),
        httpx.Response(401, json={"error": "invalid_client"}),
        httpx.Response(200, json={"access_token": "only"}),
    ],
)
@respx.mock
async def test_a_refresh_lightdash_fails_can_be_retried(http, settings, redis, answer):
    client, tokens = await sign_in(http, settings, redis)
    route = respx.post(TOKEN_URL).mock(side_effect=[answer])

    failed = await refresh(http, client, tokens["refresh_token"])

    grant = await stored_grant(settings, redis)
    assert retryable(failed), failed.text
    assert grant

    route.mock(side_effect=None, return_value=REFRESHED)

    retried = await refresh(http, client, tokens["refresh_token"])

    assert retried.status_code == 200


@respx.mock
async def test_a_refresh_while_the_grant_is_busy_can_be_retried(http, settings, redis, held_lock):
    client, tokens = await sign_in(http, settings, redis)
    route = respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    async with held_lock:
        failed = await refresh(http, client, tokens["refresh_token"])

    grant = await stored_grant(settings, redis)
    assert retryable(failed), failed.text
    assert not route.called
    assert grant

    retried = await refresh(http, client, tokens["refresh_token"])

    assert retried.status_code == 200


async def test_a_code_exchange_while_the_grant_is_busy_can_be_retried(
    http, settings, redis, held_lock
):
    client = await register(http)
    code = await add_code(settings, redis, client)

    async with held_lock:
        failed = await exchange(http, client, code)

    assert retryable(failed), failed.text

    retried = await exchange(http, client, code)

    assert retried.status_code == 200


@respx.mock
async def test_a_reused_refresh_token_while_the_grant_is_busy_still_ends_the_grant(
    http, settings, redis, held_lock
):
    client, tokens = await sign_in(http, settings, redis)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

    rotated = await refresh(http, client, tokens["refresh_token"])

    assert rotated.status_code == 200

    # Reuse is found while the token loads, outside the SDK's error handling: the grant can't end
    # with its lock busy.
    async with held_lock:
        failed = await refresh(http, client, tokens["refresh_token"])

    grant = await stored_grant(settings, redis)
    assert retryable(failed), failed.text
    assert not revoke.called
    assert grant

    reused = await refresh(http, client, tokens["refresh_token"])

    ended = await stored_grant(settings, redis)
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"
    assert ended is None


@respx.mock
async def test_a_revocation_while_the_grant_is_busy_can_be_retried(
    http, settings, redis, held_lock
):
    client, tokens = await sign_in(http, settings, redis)
    revoke = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    form = revocation_form(client, tokens["access_token"])

    async with held_lock:
        failed = await http.post("/revoke", data=form)

    grant = await stored_grant(settings, redis)
    # RFC 7009 section 2.2.1: the client must assume the token still works, and may retry.
    assert failed.status_code == 503, failed.text
    assert failed.headers["retry-after"]
    assert not revoke.called
    assert grant

    retried = await http.post("/revoke", data=form)

    ended = await stored_grant(settings, redis)
    assert retried.status_code == 200
    assert ended is None


@respx.mock
async def test_a_refresh_that_outlasts_the_lock_still_returns_its_tokens(
    http, settings, redis, monkeypatch
):
    client, tokens = await sign_in(http, settings, redis)
    monkeypatch.setattr(store_module, "LOCK_TIMEOUT", 0.05)

    async def slow_refresh(request):
        await asyncio.sleep(0.2)
        return REFRESHED

    respx.post(TOKEN_URL).mock(side_effect=slow_refresh)

    # The new tokens are saved and the old refresh token rotated: an error here would leave the
    # client with neither.
    refreshed = await refresh(http, client, tokens["refresh_token"])

    assert refreshed.status_code == 200, refreshed.text

    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    refreshed_again = await refresh(http, client, refreshed.json()["refresh_token"])

    assert refreshed_again.status_code == 200


def fail(monkeypatch: pytest.MonkeyPatch, target: object, name: str) -> None:
    async def redis_is_down(*args, **kwargs):
        raise ConnectionError("Redis is down")

    monkeypatch.setattr(target, name, redis_is_down)


def fail_command(monkeypatch: pytest.MonkeyPatch, redis: FakeAsyncRedis, step: int) -> list[str]:
    """Fail the Redis command number `step`, from 0. Returns the failed command's name, once it
    fails.

    Transactions aren't counted: a pipeline sends them on its own, without the client's
    execute_command.
    """
    original = redis.execute_command
    sent = 0
    failed = []

    async def execute(*args, **kwargs):
        nonlocal sent
        command_number = sent
        sent += 1

        if command_number == step:
            failed.append(args[0])
            raise ConnectionError("Redis is down")

        return await original(*args, **kwargs)

    monkeypatch.setattr(redis, "execute_command", execute)

    return failed


# Sent once the new tokens or the grant's end are written: the lock's release, and the client
# registration's renewal.
AFTER_THE_WRITE = ("EVALSHA", "SCRIPT LOAD", "EXPIRE")


async def refresh_with_a_failing_command(
    http: httpx.AsyncClient,
    settings: Settings,
    redis: FakeAsyncRedis,
    step: int,
) -> str | None:
    """Refreshes a new sign-in with the Redis command number `step` failing, and checks that the
    client can carry on. Returns the failed command, or None once the refresh sends fewer
    commands."""
    grant_id = f"grant-{step}"
    client, tokens = await sign_in(http, settings, redis, grant_id)

    with pytest.MonkeyPatch.context() as down:
        failed = fail_command(down, redis, step)
        response = await refresh(http, client, tokens["refresh_token"])

    if not failed:
        return None

    grant = await stored_grant(settings, redis, grant_id)

    if failed[0] in AFTER_THE_WRITE:
        assert response.status_code == 200, (failed, response.text)
        assert grant, failed
        assert grant.refresh_digest == digest(response.json()["refresh_token"]), failed
    else:
        assert retryable(response), (failed, response.text)
        assert grant, failed
        assert grant.refresh_digest == digest(tokens["refresh_token"]), failed

        retried = await refresh(http, client, tokens["refresh_token"])

        assert retried.status_code == 200, failed

    return failed[0]


async def exchange_with_a_failing_command(
    http: httpx.AsyncClient,
    settings: Settings,
    redis: FakeAsyncRedis,
    step: int,
) -> tuple[str | None, bool]:
    """Exchanges a new sign-in's code with the Redis command number `step` failing, and checks
    that the client can carry on. Returns the failed command, None once the exchange sends fewer
    commands, and whether its failure spent the code."""
    store = Store(redis, settings.fernet_key)
    client = await register(http)
    code = await add_code(settings, redis, client, f"grant-{step}")

    with pytest.MonkeyPatch.context() as down:
        failed = fail_command(down, redis, step)
        response = await exchange(http, client, code)

    if not failed:
        return None, False

    if failed[0] in AFTER_THE_WRITE:
        assert response.status_code == 200, (failed, response.text)

        return failed[0], False

    assert retryable(response), (failed, response.text)

    # Taken by GETDEL before the tokens are written: a failure after it spends the code.
    pending = await store.get("code", digest(code), Code)
    is_spent = pending is None

    retried = await exchange(http, client, code)

    expected_status = 400 if is_spent else 200
    expected_error = "invalid_grant" if is_spent else None
    assert retried.status_code == expected_status, failed
    assert retried.json().get("error") == expected_error, failed

    return failed[0], is_spent


async def revoke_with_a_failing_command(
    http: httpx.AsyncClient,
    settings: Settings,
    redis: FakeAsyncRedis,
    step: int,
) -> str | None:
    """Revokes a new sign-in's access token with the Redis command number `step` failing, and
    checks that the client can carry on. Returns the failed command, or None once the revocation
    sends fewer commands."""
    grant_id = f"grant-{step}"
    client, tokens = await sign_in(http, settings, redis, grant_id)
    form = revocation_form(client, tokens["access_token"])

    with pytest.MonkeyPatch.context() as down:
        failed = fail_command(down, redis, step)
        response = await http.post("/revoke", data=form)

    if not failed:
        return None

    if failed[0] in AFTER_THE_WRITE:
        assert response.status_code == 200, (failed, response.text)
    else:
        grant = await stored_grant(settings, redis, grant_id)
        retry_after = response.headers.get("retry-after")
        assert response.status_code == 503, (failed, response.text)
        assert retry_after == "5", (failed, response.text)
        assert grant, failed
        assert grant.access_digest == digest(tokens["access_token"]), failed

        retried = await http.post("/revoke", data=form)

        assert retried.status_code == 200, failed

    ended = await stored_grant(settings, redis, grant_id)
    assert ended is None, failed

    return failed[0]


@respx.mock
async def test_a_refresh_with_any_redis_command_failing_can_be_retried(http, settings, redis):
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    for step in itertools.count():
        failed = await refresh_with_a_failing_command(http, settings, redis, step)

        if failed is None:
            break

    assert step >= 8


async def test_a_code_exchange_with_any_redis_command_failing_is_retryable_until_the_code_is_taken(
    http, settings, redis
):
    spent = []

    for step in itertools.count():
        failed, is_spent = await exchange_with_a_failing_command(http, settings, redis, step)

        if failed is None:
            break

        if is_spent:
            spent.append(failed)

    # The grant's read, just after GETDEL. Here a failed command never runs; on Redis, a GETDEL
    # whose answer is lost has.
    assert spent == ["GET"]


@respx.mock
async def test_a_revocation_with_any_redis_command_failing_can_be_retried(http, settings, redis):
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))

    for step in itertools.count():
        failed = await revoke_with_a_failing_command(http, settings, redis, step)

        if failed is None:
            break

    assert step >= 6


@respx.mock
async def test_a_refresh_whose_token_write_fails_can_be_retried(
    http, settings, redis, monkeypatch, caplog
):
    client, tokens = await sign_in(http, settings, redis)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    with monkeypatch.context() as down:
        fail(down, Pipeline, "execute")
        failed = await refresh(http, client, tokens["refresh_token"])

    grant = await stored_grant(settings, redis)
    assert retryable(failed), failed.text
    assert failed.headers["cache-control"] == "no-store"
    assert '"storage_failed"' in caplog.text
    assert grant
    assert grant.refresh_digest == digest(tokens["refresh_token"])

    retried = await refresh(http, client, tokens["refresh_token"])

    assert retried.status_code == 200


async def test_a_code_whose_tokens_failed_to_save_is_spent(http, settings, redis, monkeypatch):
    client = await register(http)
    code = await add_code(settings, redis, client)

    with monkeypatch.context() as down:
        fail(down, Pipeline, "execute")
        failed = await exchange(http, client, code)

    # Answered as any outage, but the code was taken before the write failed: the user signs in
    # again.
    assert retryable(failed), failed.text

    spent = await exchange(http, client, code)

    assert spent.status_code == 400
    assert spent.json()["error"] == "invalid_grant"


@respx.mock
async def test_a_revocation_whose_transaction_fails_keeps_the_grant(
    http, settings, redis, monkeypatch
):
    client, tokens = await sign_in(http, settings, redis)
    lightdash = respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    form = revocation_form(client, tokens["access_token"])

    with monkeypatch.context() as down:
        fail(down, Pipeline, "execute")
        failed = await http.post("/revoke", data=form)

    grant = await stored_grant(settings, redis)
    assert failed.status_code == 503, failed.text
    assert failed.headers["retry-after"] == "5"
    assert failed.content == b""  # RFC 7009 defines no body for it
    assert not lightdash.called
    assert grant
    assert grant.access_digest == digest(tokens["access_token"])

    retried = await http.post("/revoke", data=form)

    ended = await stored_grant(settings, redis)
    assert retried.status_code == 200
    assert ended is None


async def test_a_bearer_header_during_a_redis_outage_can_be_retried(
    http, settings, redis, monkeypatch
):
    # The SDK's Bearer middleware loads the token before the endpoint, outside the routes' error
    # handling.
    client = await register(http)
    bearer = {"Authorization": "Bearer some-token"}
    refresh_form = {"grant_type": "refresh_token", "refresh_token": "r", **credentials(client)}
    fail(monkeypatch, redis, "execute_command")

    token = await http.post("/token", headers=bearer, data=refresh_form)
    revoked = await http.post("/revoke", headers=bearer, data=revocation_form(client, "t"))

    assert retryable(token), token.text
    assert revoked.status_code == 503, revoked.text


@pytest.mark.parametrize(
    ("target", "name"),
    [(Lock, "do_release"), (FakeAsyncRedis, "expire")],
    ids=["lock release", "client renewal"],
)
@respx.mock
async def test_a_refresh_saved_before_redis_fails_still_returns_its_tokens(
    http, settings, redis, monkeypatch, target, name
):
    client, tokens = await sign_in(http, settings, redis)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)

    with monkeypatch.context() as down:
        fail(down, target, name)
        refreshed = await refresh(http, client, tokens["refresh_token"])

    grant = await stored_grant(settings, redis)
    # The old refresh token is rotated by then: an error would leave the client with neither.
    assert refreshed.status_code == 200, refreshed.text
    assert grant
    assert grant.refresh_digest == digest(refreshed.json()["refresh_token"])


async def test_a_redis_outage_elsewhere_is_still_a_server_error(settings, redis, monkeypatch):
    transport = httpx.ASGITransport(asgi_app(settings, redis), raise_app_exceptions=False)
    fail(monkeypatch, redis, "execute_command")

    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8000") as http:
        consent = await http.get("/oauth/consent", params={"transaction": "t"})

    assert consent.status_code == 500


async def test_large_token_bodies_are_refused_before_they_are_read(http):
    headers = {"Authorization": basic(b"client:secret")}
    too_large = b"a=" + b"x" * 100_000

    async def chunks():
        for _ in range(100):
            yield b"x" * 1024

    declared = await http.post("/token", headers=headers, content=too_large)
    streamed = await http.post("/revoke", headers=headers, content=chunks())

    assert declared.status_code == 413
    assert streamed.status_code == 413


async def test_the_audit_log_is_one_json_line_per_call(caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    name = 'list_projects\n{"event": "tool_call", "user": "admin", "tool": "delete_everything"}'
    arguments = {"body": "x" * 10_000, "dry_run": False}
    context = SimpleNamespace(method="tools/call", params={"name": name, "arguments": arguments})

    async def call_next(_):
        return {"isError": False}

    await audit(context, call_next)

    [line] = audit_messages(caplog)
    logged = json.loads(line)
    assert "\n" not in line
    assert logged["event"] == "tool_call"
    assert logged["tool"] == name
    assert logged["error"] is False
    assert logged["arguments"]["dry_run"] is False
    assert len(logged["arguments"]["body"]) == MAX_VALUE + 3


@respx.mock
async def test_the_audit_log_follows_a_sign_in_without_its_secrets(http, settings, redis, caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    client = await register(http)
    code = await add_code(settings, redis, client)
    exchanged = await exchange(http, client, code)
    respx.post(TOKEN_URL).mock(return_value=REFRESHED)
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    refreshed = await refresh(http, client, exchanged.json()["refresh_token"])
    tokens = refreshed.json()
    revocation = {"token": tokens["refresh_token"], **credentials(client)}

    await http.post("/revoke", data=revocation)

    lines = audit_lines(caplog)
    events = [line["event"] for line in lines]
    secrets = [
        client["client_secret"],
        tokens["access_token"],
        tokens["refresh_token"],
        "ld-refresh-2",
        "lightdash-secret",
    ]
    leaked = [secret for secret in secrets if secret in caplog.text]
    assert events == [
        "client_registered",
        "token_revoked",
        "grant_ended",
    ]
    assert lines[-1]["reason"] == "revoked"
    assert not leaked


@respx.mock
async def test_a_revocation_while_the_grant_is_busy_logs_no_token_revoked(
    http, settings, redis, held_lock, caplog
):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    respx.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    client, tokens = await sign_in(http, settings, redis)
    form = revocation_form(client, tokens["access_token"])

    async with held_lock:
        failed = await http.post("/revoke", data=form)

    grant = await stored_grant(settings, redis)
    lines = audit_lines(caplog)
    events = [line["event"] for line in lines]
    busy = lines[-1]
    busy_records = [record for record in caplog.records if "revoke_busy" in record.getMessage()]
    busy_levels = [record.levelno for record in busy_records]
    assert failed.status_code == 503, failed.text
    assert grant
    assert events == ["client_registered", "revoke_busy"]
    assert busy["grant"] == "grant"
    assert busy["subject"] == "user"
    assert busy["client_id"] == client["client_id"]
    assert busy_levels == [logging.WARNING]


async def test_stopping_closes_the_http_client_and_redis(settings, redis, monkeypatch):
    closed = []

    async def close_redis(self) -> None:
        closed.append("redis")

    async def fail_to_close(self) -> None:
        raise RuntimeError("aclose failed")

    monkeypatch.setattr(Store, "close", close_redis)
    monkeypatch.setattr(httpx.AsyncClient, "aclose", fail_to_close)
    server = create_server(settings, redis)
    app = server.streamable_http_app()

    with pytest.raises(RuntimeError, match="aclose failed"):
        async with app.router.lifespan_context(app):
            pass

    # Closed even though closing the HTTP client failed.
    assert closed == ["redis"]


def test_redis_requests_time_out(settings, monkeypatch):
    created = {}
    real_from_url = server_module.Redis.from_url

    def from_url(url, **options):
        created.update(options)
        return FakeAsyncRedis()

    monkeypatch.setattr(server_module.Redis, "from_url", from_url)

    create_server(settings)

    retry = created["retry"]
    redis = real_from_url(settings.redis_url, **created)
    connection = redis.connection_pool.make_connection()
    assert created["socket_timeout"]
    assert created["socket_connect_timeout"]
    # The async Retry, not redis.retry's.
    assert isinstance(retry, Retry)
    assert retry.get_retries() == 1
    # The commands retry with the pool's connections' policy, not the client's.
    assert connection.retry.get_retries() == 1


@pytest.mark.parametrize(
    ("authorization", "expected"),
    [
        ("Basic not-base64!", None),
        (basic(b"\xff\xfe:secret"), None),
        (basic(b"no-separator"), None),
        (basic(b":secret"), None),
        ("basic " + base64.b64encode(b"client:secret").decode(), None),
        ("Bearer token", None),
        (basic(b"client:secret"), ("client", "secret")),
        (basic(b"my%20client:se%3Acret"), ("my client", "se:cret")),
        (basic(b"client:sec:ret"), ("client", "sec:ret")),
        (basic(b"client:"), ("client", "")),
    ],
)
def test_basic_credentials_are_read_strictly(authorization, expected):
    result = _basic_credentials(authorization)

    assert result == expected


async def test_a_garbage_basic_header_is_refused_without_a_server_error(http, settings, redis):
    client = await register(http, "client_secret_basic")
    code = await add_code(settings, redis, client)
    form = code_form(code) | {"client_id": client["client_id"]}
    garbage = ["Basic not-base64!", basic(b"\xff\xfe:x"), basic(b"no-separator"), "Basic "]

    for authorization in garbage:
        headers = {"Authorization": authorization}
        response = await http.post("/token", headers=headers, data=form)

        assert response.status_code == 401, authorization
        assert response.json()["error"] == "invalid_client"

    # The refused requests didn't use the code up.
    headers = {"Authorization": basic_for(client)}
    tokens = await http.post("/token", headers=headers, data=code_form(code))

    assert tokens.status_code == 200, tokens.text


async def test_only_the_credentials_missing_from_the_form_are_added():
    body = b"grant_type=authorization_code&client_id=A"
    received = {}

    async def app(scope, receive, send):
        message = await receive()
        headers = dict(scope["headers"])
        received["form"] = parse_qs(message["body"].decode())
        received["length"] = headers[b"content-length"]

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    headers = [
        (b"authorization", basic(b"B:secret-b").encode()),
        (b"content-length", str(len(body)).encode()),
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/token",
        "headers": headers,
    }
    middleware = BasicAuthClientId(app)

    await middleware(scope, receive, None)

    added = b"&client_secret=secret-b"
    assert received["form"] == {
        "grant_type": ["authorization_code"],
        "client_id": ["A"],
        "client_secret": ["secret-b"],
    }
    assert received["length"] == str(len(body) + len(added)).encode()


async def test_a_basic_header_cannot_authenticate_another_form_client(http, settings, redis):
    victim = await register(http)
    attacker = await register(http)
    code = await add_code(settings, redis, victim)
    headers = {"Authorization": basic_for(attacker)}
    form = code_form(code) | {"client_id": victim["client_id"]}

    response = await http.post("/token", headers=headers, data=form)

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"

    exchanged = await exchange(http, victim, code)

    assert exchanged.status_code == 200


async def add_access(settings: Settings, redis: FakeAsyncRedis, token: str) -> None:
    """A signed-in user whose access token to this server is `token`."""
    store = Store(redis, settings.fernet_key)
    grant = Grant(
        client_id="client",
        subject="user",
        access_token="ld-access",
        refresh_token="ld-refresh",
        expires_at=time.time() + TOKEN_LIFETIME,
        access_digest=digest(token),
    )
    access = Access(
        token=token,
        client_id="client",
        scopes=[],
        subject="user",
        grant_id="grant",
    )

    await store.put("grant", "grant", grant)
    await store.put("access", digest(token), access)


async def test_requests_to_mcp_need_an_allowed_host_and_origin(redis):
    settings = make_settings(public_url="https://mcp.example.com")
    token = "our-access"
    await add_access(settings, redis, token)
    security = transport_security(settings)
    server = create_server(settings, redis)
    app = server.streamable_http_app(transport_security=security)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
    }
    cases = [
        ({"Host": "evil.example"}, 421),
        ({"Host": "mcp.example.com", "Origin": "https://evil.example"}, 403),
        ({"Host": "mcp.example.com", "Origin": "http://mcp.example.com"}, 403),
        ({"Host": "mcp.example.com", "Origin": "https://mcp.example.com"}, 200),
        ({"Host": "localhost:8000", "Origin": "http://localhost:8000"}, 200),
    ]
    transport = httpx.ASGITransport(app)
    http = httpx.AsyncClient(transport=transport, base_url="https://mcp.example.com")

    async with app.router.lifespan_context(app), http:
        for host_and_origin, status in cases:
            sent = headers | host_and_origin
            response = await http.post("/mcp", headers=sent, json=INITIALIZE)

            assert response.status_code == status, (host_and_origin, response.text)


async def test_a_code_exchange_keeps_the_client(http, settings, redis):
    client = await register(http)
    key = f"lightdash-mcp:client:{client['client_id']}"
    await redis.expire(key, 60)
    code = await add_code(settings, redis, client)

    response = await exchange(http, client, code)

    ttl = await redis.ttl(key)
    assert response.status_code == 200, response.text
    assert ttl > CLIENT_TTL - 60


async def test_the_audit_log_marks_failed_calls(caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")

    async def raising(_):
        raise RuntimeError("boom")

    async def error_dict(_):
        return {"isError": True}

    async def error_model(_):
        return CallToolResult(content=[], is_error=True)

    async def success_model(_):
        return CallToolResult(content=[])

    with pytest.raises(RuntimeError, match="boom"):
        await audit(tool_call(), raising)

    from_dict = await audit(tool_call(), error_dict)
    from_model = await audit(tool_call(), error_model)
    await audit(tool_call(), success_model)

    errors = [line["error"] for line in audit_lines(caplog)]
    assert from_dict == {"isError": True}
    assert from_model.is_error
    assert errors == [True, True, True, False]


async def test_the_audit_log_leaves_out_other_requests(caplog):
    caplog.set_level(logging.INFO, "lightdash_mcp.audit")
    others = [
        SimpleNamespace(method="tools/list", params={"name": "list_projects"}),
        SimpleNamespace(method="tools/call", params=None),
    ]

    async def call_next(_):
        return {"tools": []}

    for context in others:
        result = await audit(context, call_next)

        assert result == {"tools": []}

    assert audit_lines(caplog) == []


def test_logged_arguments_are_capped():
    many = {f"argument{number}": number for number in range(MAX_ITEMS + 5)}
    numbers = list(range(1000))

    kept_names = list(clip_arguments(many))

    assert kept_names == list(many)[:MAX_ITEMS]
    assert clip_arguments("x" * 1000) == "x" * MAX_VALUE + "..."
    assert clip_arguments([1, 2]) == [1, 2]
    assert clip_arguments(numbers) == json.dumps(numbers)[:MAX_VALUE] + "..."
